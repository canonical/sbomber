"""Sbom client."""

import logging
import math
import mimetypes
import os
import os.path
from collections import namedtuple
from io import BufferedReader
from pathlib import Path
from typing import Dict, Mapping, Optional, Union

import requests
import tenacity

from clients.client import Client, DownloadError, UploadError, WaitError
from state import Artifact, ArtifactType, ProcessingStatus, UbuntuRelease

mimetypes.init()
mimetypes.suffix_map[".charm"] = ".zip"
mimetypes.suffix_map[".rock"] = ".tar"
mimetypes.add_type("application/octet-stream", ".snap")

logger = logging.getLogger(__name__)

# TODO: replace with stable non-test URL once it becomes live
DEFAULT_SERVICE_URL = "https://sbom-request.canonical.com"
MB_TO_BYTES = 1024 * 1024
CHUNK_SIZE = 1 * MB_TO_BYTES

Chunk = namedtuple("Chunk", ["index", "size", "read"])


def partial_read(file: BufferedReader, start: int, length: int) -> bytes:
    """Read length number of bytes from start from file."""
    file.seek(start)
    return file.read(length)


class SBOMber(Client):
    """Sbomber tool."""

    # service api docs: https://sbom-request.canonical.com/docs
    _status_map = {
        "Completed": ProcessingStatus.success,
        "Pending": ProcessingStatus.pending,
        "completed": ProcessingStatus.success,
        "pending": ProcessingStatus.pending,
        "processing": ProcessingStatus.pending,
    }

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

    def submit(self, filename: Union[str, Path], artifact: Artifact) -> str:
        """Submit an sbom request."""
        if version := artifact.version is None:
            # TODO: can we fix this automatically?
            version = "0"
            logger.warning(
                "`version` is likely required for SBOM client: using `0` instead. "
                "You might experience inconsistencies."
            )

        if not os.path.isfile(filename):
            raise ValueError(f"The provided filename {filename} doesn't exist.")

        print(f"Submitting {filename} (version {version!r})...")
        return self._upload(Path(filename), artifact, str(version))

    def wait(
        self,
        token: str,
        timeout: Optional[int] = None,
        status: ProcessingStatus = ProcessingStatus.success,
    ):
        """Wait for `timeout` minutes for the remote SBOM generation to complete."""
        print(f"Awaiting {token} SBOM")

        for attempt in tenacity.Retrying(
            # give this method some time to pass (by default 15 minutes)
            stop=tenacity.stop_after_delay(60 * (timeout or 15)),
            # wait 5 sec between tries
            wait=tenacity.wait_fixed(5),
            # if you don't succeed raise the last caught exception when you're done
            reraise=True,
        ):
            with attempt:
                current_status = self.query_status(token)
                if current_status != status:
                    raise TimeoutError(
                        f"timeout waiting for status {status}; last: {current_status}"
                    )

    def download_report(self, token: str, output_file: Union[str, Path, None] = None):
        """Download SBOM report for the given artifact ID."""
        sbom_url = f"{self._service_url}/api/v1/artifacts/sbom/{token}"
        headers = {"Accept": "application/octet-stream"}

        print(f"Downloading SBOM for artifact ID: {token}")

        response = requests.get(sbom_url, headers=headers)

        if response.status_code != 200:
            raise DownloadError(
                f"Failed to download SBOM. Status code: {response.status_code}, Response: "
                f"{response.text}"
            )

        sbom_content = response.text

        # Save to file if output_file is specified
        if output_file:
            Path(output_file).write_text(sbom_content)
            print(f"SBOM saved to {output_file}")

    def _chunked_upload(self, file_path: Path, token: str):
        # Get file stats
        file_size = os.path.getsize(file_path)
        file_name = self._sanitize_filename(file_path)

        mimetype, _ = mimetypes.guess_type(file_name)

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
                    "resumableType": mimetype,
                    "resumableIdentifier": f"{file_name}-{i}",
                    "resumableFilename": file_name,
                    "resumableTotalChunks": str(total_chunks),
                }

                response = requests.post(
                    f"{self._service_url}/api/v1/artifacts/upload/chunk/{token}",
                    files=files,
                    data=data,
                )

                if response.status_code != 200:
                    raise Exception(
                        f"Failed to upload chunk {i}. Status code: {response.status_code}, "
                        f"Response: {response.text}"
                    )

                logger.debug(f"Artifact {token}: Chunk {i}/{total_chunks} uploaded")
                print("." if i % 10 != 0 else i, end="", flush=True)
                self._verify_chunk_upload(token, i)

        print()  # newline after the dots
        return total_chunks

    def _verify_chunk_upload(self, token: str, chunk_number: int):
        verify_url = (
            f"{self._service_url}/api/v1/artifacts/upload/chunk/"
            f"{token}?resumableChunkNumber={chunk_number}"
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

        logger.debug(f"Artifact {token}: chunk {chunk_number} verified.")

    @staticmethod
    def upload_props(atype: ArtifactType) -> Dict[str, str]:
        """Per-artifact properties for the upload request."""
        return {}

    def _register_artifact(self, path: Path, artifact: Artifact, version: str):
        """Submit an artifact's metadata to obtain a token."""
        # todo: support "compressionFormat"
        type_to_format = {
            ArtifactType.charm: "charm",
            ArtifactType.deb: "deb",
            ArtifactType.rock: "tar",
            ArtifactType.snap: "snap",
        }

        filename = self._sanitize_filename(path)

        json_body: Mapping[str, str | Mapping[str, str]] = {
            "artifactName": path.stem,
            "version": version,
            "filename": filename,
            **self._owner,
            "artifactFormat": type_to_format[artifact.type],
        }

        if artifact.type == ArtifactType.deb:
            if any(x is None for x in [artifact.variant, artifact.arch, artifact.base]):
                raise ValueError("variant, arch and base are required for deb artifacts.")
            json_body["variant"] = {"value": artifact.variant, "type": "predefined"}
            json_body["architecture"] = {"value": artifact.arch, "type": "predefined"}
            json_body["release"] = {
                "value": UbuntuRelease[artifact.base].value,  # type: ignore
                "type": "predefined",
            }

        type_to_path = {
            ArtifactType.charm: "charm",
            ArtifactType.deb: "ubuntu",
            ArtifactType.rock: "source",
            ArtifactType.snap: "snap",
        }

        url = f"{self._service_url}/api/v1/artifacts/{type_to_path[artifact.type]}/upload"
        try:
            response = requests.post(url, json=json_body)
            response_json = response.json()
        except ConnectionError:
            raise UploadError("DNS error: are you connected to the VPN?")
        except Exception:
            logger.exception(f"failed to post submit request to {url} with json: {json_body}")
            raise UploadError(f"invalid response from {url}")

        token = response_json.get("data", {}).get("artifactId")

        if not token:
            raise UploadError(f"server didn't respond with an `artifactId`: {response_json}")

        print(f"registered {path} as {token}")
        return token

    def _sanitize_filename(self, path):
        filename = path.name
        # certain types expect specific filenames
        suffix_map = {".rock": ".tar"}
        if map_to := suffix_map.get(path.suffix):
            filename = path.with_suffix(map_to).name
        return filename

    def _upload(self, path: Path, artifact: Artifact, version: str) -> str:
        """Chunked source upload."""
        token = self._register_artifact(path, artifact, version)
        logger.info(f"registered artifact at {path} with ID: {token}")
        self._chunked_upload(path, token)
        self._complete_upload(token)
        logger.debug(f"Uploaded artifact for ID: {token}")
        return token

    def query_status(self, token: str) -> ProcessingStatus:
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
            url = f"{self._service_url}/api/v1/artifacts/status/{token}/"
            response = requests.get(url)
            if response.status_code == 200:
                logger.debug(
                    f"SBOM status query successful for artifact {token}: {response.json()}"
                )
                status = response.json().get("data", {}).get("status", "Pending")
                error = response.json().get("data", {}).get("metadata", {}).get("error")
                logger.debug(
                    f"SBOM generation status for artifact {token}: {status}, error: {error}"
                )
                return self._status_map.get(status, ProcessingStatus.failed)

            logger.debug(
                f"SBOM generation status query for artifact {token} failed with status code "
                f"{response.status_code} and body {response.text}"
            )
            raise WaitError(response.text)
        except requests.exceptions.RequestException as e:
            logger.exception(f"SBOM artifact {token} status query exception: {e}")
            raise WaitError(e)

    def _complete_upload(self, token):
        url = f"{self._service_url}/api/v1/artifacts/upload/complete/{token}"
        response = requests.post(url)
        if response.status_code != 200:
            raise Exception(
                f"Failed to complete upload. Status code: {response.status_code}, Response: {response.text}"
            )

        response_data = response.json()
        expected_response = {"message": "Upload completed successfully"}

        if response_data != expected_response:
            raise Exception(
                f"Upload completion failed. Expected: {expected_response}, Got: {response_data}"
            )

        print("upload completed.")
