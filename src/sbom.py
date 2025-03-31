"""Sbom client."""

import logging
import math
import os
import os.path
from collections import namedtuple
from enum import Enum
from io import BufferedReader
from pathlib import Path
from typing import Optional, Union

import requests
import tenacity

logger = logging.getLogger(__name__)

# TODO: replace with stable non-test URL once it becomes live
DEFAULT_SERVICE_URL = "https://sbom-request-test.canonical.com"
MB_TO_BYTES = 1024 * 1024
CHUNK_SIZE = 1 * MB_TO_BYTES


class ProcessingStatus(str, Enum):
    """Processing status."""

    pending = "Pending"
    success = "Succeeded"
    failed = "Failed"


class ArtifactType(str, Enum):
    """ArtifactType."""

    charm = "charm"
    rock = "rock"
    snap = "snap"

    @staticmethod
    def from_path(path: Path) -> "ArtifactType":
        """Instantiate from path."""
        if path.name.endswith(".charm"):
            return ArtifactType.charm
        if path.name.endswith(".rock"):
            return ArtifactType.rock
        if path.name.endswith(".snap"):
            return ArtifactType.snap
        raise NotImplementedError(path.suffix)

    @property
    def upload_props(self):
        """Per-artifact properties for the upload request."""
        type_to_format = {
            ArtifactType.charm: "charm",
            ArtifactType.rock: "tar",
            ArtifactType.snap: "snap",
        }
        return {"artifactFormat": type_to_format[self]}

    @property
    def scanner_args(self):
        """Per-artifact CLI args for the sec scanner cli."""
        type_to_format = {
            ArtifactType.charm: "charm",
            ArtifactType.rock: "oci",
            # ArtifactType.snap: "snap",
        }
        type_to_type = {
            ArtifactType.charm: "package",
            ArtifactType.rock: "container-image",
            # ArtifactType.snap: "snap",
        }
        return ["--format", type_to_format[self], "--type", type_to_type[self]]


Chunk = namedtuple("Chunk", ["index", "size", "read"])


def partial_read(file: BufferedReader, start: int, length: int) -> bytes:
    """Read length number of bytes from start from file."""
    file.seek(start)
    return file.read(length)


class WaitError(RuntimeError):
    """Raised by SBOMber if a request for updates fails."""


class DownloadError(RuntimeError):
    """Raised by SBOMber if a downloading a sbom fails."""


class UploadError(RuntimeError):
    """Raised by SBOMber if uploading an artifact fails."""


class SBOMber:
    """Sbomber tool."""

    # service api docs: https://sbom-request-test.canonical.com/docs
    _status_map = {"Completed": ProcessingStatus.success, "Pending": ProcessingStatus.pending}

    def __init__(
        self,
        department: str,
        team: str,
        email: str,
        maintainer: str = "Canonical",
        service_url: Optional[str] = None,
    ):
        """Init this thing."""
        self._service_url = service_url or DEFAULT_SERVICE_URL
        self._owner = {
            "maintainer": maintainer,
            "email": email,
            "department": {"value": department, "type": "predefined"},
            "team": {"value": team, "type": "predefined"},
        }

    def sbomb(
        self,
        filename: Union[str, Path],
        atype: str,
        version: Union[int, str],
        timeout: int = 15,
    ):
        """End-to-end sbom submission flow."""
        artifact_id = self.request_sbom(filename, ArtifactType(atype), version)
        self.wait(artifact_id, timeout=timeout)
        self.download_report(artifact_id)

    def request_sbom(
        self, filename: Union[str, Path], atype: str, version: Union[int, str]
    ) -> str:
        """Submit an sbom request."""
        if not os.path.isfile(filename):
            raise ValueError(f"The provided filename {filename} doesn't exist.")
        print(f"Uploading {filename} (version {version!r})...")
        return self._upload(Path(filename), ArtifactType(atype), str(version))

    def wait(
        self,
        artifact_id: str,
        timeout: int = None,
        status: ProcessingStatus = ProcessingStatus.success,
    ):
        """Wait for `timeout` minutes for the remote SBOM generation to complete."""
        print(f"Awaiting {artifact_id} SBOM")

        for attempt in tenacity.Retrying(
            # give this method some time to pass (by default 15 minutes)
            stop=tenacity.stop_after_delay(60 * (timeout or 15)),
            # wait 5 sec between tries
            wait=tenacity.wait_fixed(5),
            # if you don't succeed raise the last caught exception when you're done
            reraise=True,
        ):
            with attempt:
                current_status = self.query_status(artifact_id)
                if current_status != status:
                    raise TimeoutError(
                        f"timeout waiting for status {status}; last: {current_status}"
                    )

    def download_report(self, artifact_id: str, output_file: Union[str, Path] = None):
        """Download SBOM report for the given artifact ID."""
        sbom_url = f"{self._service_url}/api/v1/artifacts/sbom/{artifact_id}"
        headers = {"Accept": "application/octet-stream"}

        print(f"Downloading SBOM for artifact ID: {artifact_id}")

        response = requests.get(sbom_url, headers=headers)

        if response.status_code != 200:
            raise Exception(
                f"Failed to download SBOM. Status code: {response.status_code}, Response: "
                f"{response.text}"
            )

        sbom_content = response.text

        # Save to file if output_file is specified
        if output_file:
            Path(output_file).write_text(sbom_content)
            print(f"SBOM saved to {output_file}")

    def _chunked_upload(self, file_path, artifact_id):
        # Get file stats
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        total_chunks = math.ceil(file_size / CHUNK_SIZE)

        print(f"Starting chunked upload for {file_name} ({total_chunks} chunks): ", end="")
        logger.debug(
            f"File size: {file_size} bytes, Chunk size: {CHUNK_SIZE} bytes, Total chunks: "
            f"{total_chunks}"
        )

        with open(file_path, "rb") as file:
            for i in range(1, total_chunks + 1):
                chunk = file.read(CHUNK_SIZE)
                # the final chunk may be smaller
                current_chunk_size = len(chunk)

                files = {"file": (file_name, chunk, "application/octet-stream")}

                data = {
                    "resumableChunkNumber": str(i),
                    "resumableChunkSize": str(CHUNK_SIZE),
                    "resumableCurrentChunkSize": str(current_chunk_size),
                    "resumableTotalSize": str(file_size),
                    "resumableType": "application/x-tar",  # MIME type for tar files
                    "resumableIdentifier": f"{file_name}-{i}",
                    "resumableFilename": file_name,
                    "resumableTotalChunks": str(total_chunks),
                }

                response = requests.post(
                    f"{self._service_url}/api/v1/artifacts/upload/chunk/{artifact_id}",
                    files=files,
                    data=data,
                )

                if response.status_code != 200:
                    raise Exception(
                        f"Failed to upload chunk {i}. Status code: {response.status_code}, "
                        f"Response: {response.text}"
                    )

                logger.debug(f"Artifact {artifact_id}: Chunk {i}/{total_chunks} uploaded")
                print(".", end="", flush=True)
                self._verify_chunk_upload(artifact_id, i)

        print()  # newline after the dots
        return total_chunks

    def _verify_chunk_upload(self, artifact_id: str, chunk_number: int):
        verify_url = (
            f"{self._service_url}/api/v1/artifacts/upload/chunk/"
            f"{artifact_id}?resumableChunkNumber={chunk_number}"
        )

        headers = {"Accept": "application/json"}

        response = requests.get(verify_url, headers=headers)

        if response.status_code != 200:
            raise Exception(
                f"Failed to verify chunk {chunk_number}. Status code: {response.status_code}, "
                f"Response: {response.text}"
            )

        response_data = response.json()
        expected_response = {"data": True, "message": "Chunk Found"}

        if response_data != expected_response:
            raise Exception(
                f"Chunk verification failed. Expected: {expected_response}, Got: {response_data}"
            )

        logger.debug(f"Artifact {artifact_id}: chunk {chunk_number} verified.")

    def _register_artifact(self, path: Path, atype: ArtifactType, version: str):
        """Submit an artifact's metadata to obtain an artifact ID."""
        # todo: support "compressionFormat"
        json_body = {
            "artifactName": path.stem,
            "version": version,
            "filename": path.name,
            **self._owner,
            **atype.upload_props,
        }
        url = f"{self._service_url}/api/v1/artifacts/{atype.value}/upload"
        try:
            response = requests.post(url, json=json_body)
            response_json = response.json()
        except ConnectionError:
            exit("DNS error: are you connected to the VPN?")
        except Exception:
            logger.exception(f"failed to post submit request to {url} with json: {json_body}")
            exit(f"invalid response from {url}")

        artifact_id = response_json.get("data", {}).get("artifactId")

        if not artifact_id:
            raise UploadError(f"server didn't respond with an `artifactId`: {response_json}")

        print(f"registered {path} as {artifact_id}")
        return artifact_id

    def _upload(self, path: Path, atype: ArtifactType, version: str) -> str:
        """Chunked source upload."""
        artifact_id = self._register_artifact(path, atype, version)
        logger.info(f"registered artifact at {path} with ID: {artifact_id}")
        self._chunked_upload(path, artifact_id)
        logger.debug(f"Uploaded artifact for ID: {artifact_id}")
        return artifact_id

    def query_status(self, artifact_id: str) -> ProcessingStatus:
        """Query the status of an SBOM request.

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
                logger.debug(
                    f"SBOM status query successful for artifact {artifact_id}: {response.json()}"
                )
                status = response.json().get("status", "Pending")
                error = response.json().get("metadata", {}).get("error")
                logger.debug(
                    f"SBOM generation status for artifact {artifact_id}: {status}, error: {error}"
                )
                return self._status_map.get(status, ProcessingStatus.failed)

            logger.debug(
                f"SBOM generation status query for artifact {artifact_id} failed with status code "
                f"{response.status_code} and body {response.text}"
            )
            raise WaitError(response.text)
        except requests.exceptions.RequestException as e:
            logger.exception(f"SBOM artifact {artifact_id} status query exception: {e}")
            raise WaitError(e)
