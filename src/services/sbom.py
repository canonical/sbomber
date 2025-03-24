import logging
import os
import os.path
from collections import namedtuple
from dataclasses import dataclass
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Set, Union, List

import bs4
import requests
import tenacity

logger = logging.getLogger(__name__)

SBOM_REPORTS_DEFAULT_DIRECTORY = Path("./sboms")
CHUNK_SIZE = 5 * 1024 * 1024  # 5MB specified in bytes.


class ArtifactType(str, Enum):
    charm = "charm"
    rock = "container"
    source = "source"

    @staticmethod
    def from_path(path: Path) -> "ArtifactType":
        if path.name.endswith(".charm"):
            return ArtifactType.charm
        elif path.name.endswith(".rock"):
            return ArtifactType.rock
        else:
            return ArtifactType.source


@dataclass(frozen=True)
class ArtifactProperties:
    old_type: str
    format: str
    compression: str


ARTIFACT_PROPERTIES: dict[ArtifactType, ArtifactProperties] = {
    ArtifactType.charm: ArtifactProperties(
        old_type="binary",
        format="charm",
        compression="",
    ),
    ArtifactType.rock: ArtifactProperties(
        old_type="container",
        format="tar",
        compression="",
    ),
    ArtifactType.source: ArtifactProperties(
        old_type="binary",
        format="tar",
        compression="gz",
    ),
}
Chunk = namedtuple('Chunk', ['index', 'size', 'read'])


def partial_read(path: Path, start: int, length: int) -> bytes:
    """Read length number of bytes from start from file."""
    with open(path, "rb") as file:
        file.seek(start)
        return file.read(length)


class WaitError(RuntimeError):
    """Raised by SBOMber if a request for updates fails."""


class DownloadError(RuntimeError):
    """Raised by SBOMber if a downloading a sbom fails."""


class UploadError(RuntimeError):
    """Raised by SBOMber if uploading an artifact fails."""


class SBOMber:
    _service_url = "https://sbom-request.canonical.com"

    def __init__(self, department: str, team: str, email: str, reports_dir: Path = SBOM_REPORTS_DEFAULT_DIRECTORY):
        self._owner = {
            "email": email,
            "department": department,
            "team": team,
        }
        self._reports_dir = Path(reports_dir)

    def sbomb(self, filename: str, version: Union[int, str], timeout: int = 15):
        """End-to-end sbom submission flow."""
        artifact_id = self.request_sbom(filename, version)
        self.wait(artifact_id, timeout=timeout)
        self.download_report(artifact_id)

    def request_sbom(self, filename: str, version: Union[int, str]) -> str:
        if not os.path.isfile(filename):
            raise ValueError(f"The provided filename {filename} doesn't exist.")
        print(f"Uploading {filename} (version {version!r})...")
        artifact_id = self._upload(filename, str(version))
        return artifact_id

    def wait(self, artifact_id: str, timeout: int = None):
        """Wait for `timeout` minutes for the remote SBOM generation to complete."""
        print("Waiting for SBOM generation...")

        for attempt in tenacity.Retrying(
                retry=tenacity.retry_if_not_result(lambda s: s == "completed") and tenacity.retry_if_exception(
                    lambda e: True),
                # give this method some time to pass (by default 15 minutes)
                stop=tenacity.stop_after_delay(60 * (timeout or 15)),
                # wait 1 minute between tries, +1m for each failed try
                wait=tenacity.wait_incrementing(60),
                # if you don't succeed raise the last caught exception when you're done
                reraise=True,
        ):
            with attempt:
                status = self._query_status(artifact_id)
                attempt.retry_state.set_result(status.lower())

    def download_report(self, artifact_id: str):
        """
        Download SBOM reports for the given artifact ID.
        """
        print("Downloading SBOM...")
        self._reports_dir.mkdir(parents=True, exist_ok=True)

        url = f"{self._service_url}/reports/{artifact_id}/"

        try:
            reports = self._get_report_filenames(url)
            self._download_reports(url, reports)
        except requests.exceptions.RequestException as e:
            raise DownloadError(f"SBOM report download for {artifact_id} failed")

    @staticmethod
    def _get_report_filenames(url):
        filenames = set()
        response = requests.get(url)
        if response.status_code != 200:
            logger.error(f"failed to query {url}")
            return filenames

        data = bs4.BeautifulSoup(response.text, "html.parser")
        for link in data.find_all("a"):
            if link["href"].endswith(".sbomqs") or link["href"].endswith(".json"):
                filenames.add(link['href'])

        return filenames

    @staticmethod
    def _download_reports(url: str, filenames: Set[str]):
        for report_filename in filenames:
            report_download_url = f"{url}{report_filename}"
            r = requests.get(report_download_url)
            if r.status_code != 200:
                logger.error(f"SBOM report download at {report_download_url} failed with "
                             f"status code {r.status_code} and body {r.text}")

            filename = Path(f"{SBOM_REPORTS_DEFAULT_DIRECTORY}/{report_filename}")

            logger.info(f"Downloading {report_filename} to {filename}")
            filename.write_bytes(r.content)

    @staticmethod
    def _chunk(path: str, total_size: int) -> List[Chunk]:
        chunks = []
        start = 0
        index = 1
        while start < total_size:
            end = min(start + CHUNK_SIZE, total_size)
            size = end - start

            chunk = Chunk(index, size, partial(partial_read, path, start, size))
            chunks.append(chunk)

            index += 1
            start += CHUNK_SIZE
        return chunks

    def _chunked_upload(self, path: str, artifact_id: str):
        # Chunked file upload.
        total_size = os.path.getsize(path)

        chunks = self._chunk(path, total_size)

        for chunk in chunks:
            # See https://github.com/23/resumable.js/blob/master/README.md .
            params = {
                "resumableChunkNumber": chunk.index,  # 1-based count.
                "resumableTotalChunks": len(chunks),
                "resumableChunkSize": CHUNK_SIZE,  # Size per chunk.
                "resumableCurrentChunkSize": chunk.size,
                "resumableTotalSize": total_size,  # Total file size.
                "resumableType": "application%2Fgzip",
                "resumableIdentifier": f"{chunk.index}-{artifact_id}",
                "resumableFilename": path,
                "resumableRelativePath": path,
            }

            response = requests.post(
                f"{self._service_url}/api/v1/artifacts/upload/chunk/{artifact_id}/",
                files={'file': chunk.read()},
                params=params
            )
            if response.status_code == 200:
                logger.info(f"uploaded {artifact_id} chunk {chunk.index}/{len(chunks)}")
                # TODO:
                # self._verify_chunk_upload()

            else:
                logger.error(f"failed to upload {artifact_id} chunk {chunk.index}/{len(chunks)}")

        # Mark the chunked file upload as completed.
        response = requests.post(f"{self._service_url}/api/v1/artifacts/upload/complete/{artifact_id}/",
                                 json={
                                     "resumableFilename": str(path),
                                 })

        if response.status_code != 200:
            logger.error(f"Failed to complete upload for {path} with ID: {artifact_id}: {response.text}")
            raise UploadError(f"Failed to complete upload for {path} with ID: {artifact_id}")

    def _register_artifact(self, path: Path, version: str):
        """Submit an artifact's metadata to obtain an artifact ID."""
        artifact_type = ArtifactType.from_path(path)
        json_body = {
            "maintainer": "Canonical",
            "artifactStored": "false",
            "artifactType": f"{artifact_type.value}",
            "oldArtifactType": ARTIFACT_PROPERTIES[artifact_type].old_type,
            "sharingMethod": "upload",
            "artifactName": path.stem,
            "version": version,
            "artifactFormat": ARTIFACT_PROPERTIES[artifact_type].format,
            "compressionFormat": ARTIFACT_PROPERTIES[artifact_type].compression,
            "fileUpload": {},
            "filename": str(path),
            **self._owner
        }
        url = f"{self._service_url}/api/v1/artifacts/submit"
        try:
            response = requests.post(url, json=json_body)
        except:
            logger.exception(f"failed to post submit request to {url} with json: {json_body}")
            raise

        response_json = response.json()
        artifact_id = response_json.get("artifactId")

        if not artifact_id:
            raise UploadError(f"server didn't respond with an `artifactId`: {response_json}")

        return artifact_id

    def _upload(self, filename: str, version: str) -> str:
        """Chunked source upload."""
        path = Path(filename)

        artifact_id = self._register_artifact(path, version)
        logger.info(f"registered artifact at {path} with ID: {artifact_id}")

        self._chunked_upload(filename, artifact_id)
        logger.debug(f"Uploaded artifact for ID: {artifact_id}")

        return artifact_id

    def _query_status(self, artifact_id: str) -> str:
        """
        Query the status of an SBOM request.

        Only the "completed" status results in a downloadable report.
        Sample response from the API:
        {
            "status": "pending",
            # Optional field.
            "sbomUrl": "https://sbom-request.canonical.com/reports/<id>",
            "metadata": {
                ...
                "artifactId": "ae6f44bf-aa56-4ce1-ad9b-883a179b5282",
                "timestamp": "2025-02-22T13:31:01.701Z",
                "project": "charm-ae6f44bf-aa56-4ce1-ad9b-883a179b5282",
                # Optional field.
                "error": ""
            }
        }
        """
        try:
            response = requests.get(f"{self._service_url}/api/v1/artifacts/status/{artifact_id}/")
            if response.status_code == 200:
                logger.debug(f"SBOM status query successful for artifact {artifact_id}: {response.json()}")
                status = response.json().get("status", "Pending")
                error = response.json().get("metadata", {}).get("error")
                logger.debug(f"SBOM generation status for artifact {artifact_id}: {status}, error: {error}")
                return status
            else:
                logger.debug(
                    f"SBOM generation status query for artifact {artifact_id} failed with status code {response.status_code} and body {response.text}")
                raise WaitError(response.text)
        except requests.exceptions.RequestException as e:
            logger.exception(f"SBOM artifact {artifact_id} status query exception: {e}")
            raise WaitError(e)


if __name__ == "__main__":
    sbomber = SBOMber(
        email="pietro.pasotti@canonical.com",
        department="engineering",
        team="observability"
    )

    sbomber.sbomb(
        "/home/pietro/canonical/parca-k8s-operator/parca-k8s_ubuntu@22.04-amd64.charm",
        version=299
    )
