"""Security scanner client."""

import logging
import os
import subprocess
from enum import Enum
from pathlib import Path
from typing import List, Optional, Union

import tenacity

from clients.client import Client, DownloadError, UploadError
from state import ArtifactType, ProcessingStatus, Token

logger = logging.getLogger()


def _crop_token(token: str):
    return f"{token[:15]}...{token[-15:]}"


def _token_filename(fname: str):
    return f".{fname}.token"


class ScannerType(str, Enum):
    """ScannerType."""

    trivy = "trivy"


class Scanner(Client):
    """Scanner tool."""

    CLIENT_NAME = "secscan-client"
    _status_map = {
        "Scan has succeeded.": ProcessingStatus.success,
        "Scan request is running.": ProcessingStatus.pending,
        "Scan has failed.": ProcessingStatus.failed,
    }

    def __init__(self, scanner: ScannerType = ScannerType.trivy):
        """Init this thing."""
        self._verify_client_installed()
        self._scanner = scanner

    def _verify_client_installed(self):
        if not subprocess.run(["which", self.CLIENT_NAME]).returncode == 0:
            raise RuntimeError(f"you must install {self.CLIENT_NAME}")

    def _run(self, *cmd: str, token: Optional[str] = None):
        cmds = [self.CLIENT_NAME, "--batch", *cmd]
        proc = subprocess.run(cmds, text=True, capture_output=True, input=token)
        if proc.stderr:
            logger.error(f"captured error while running {cmds}: {proc.stderr}")
        return proc.stdout.strip()

    @staticmethod
    def scanner_args(atype: ArtifactType) -> List[str]:
        """Per-artifact CLI args for the sec scanner cli."""
        type_to_format = {
            ArtifactType.charm: "charm",
            ArtifactType.rock: "oci",
            ArtifactType.snap: "snap",
        }
        type_to_type = {
            ArtifactType.charm: "package",
            ArtifactType.rock: "container-image",
            ArtifactType.snap: "package",
        }
        return ["--format", type_to_format[atype], "--type", type_to_type[atype]]

    def submit(
        self, filename: Union[str, Path], atype: str, version: Optional[Union[int, str]] = None
    ) -> str:
        """Submit a SECSCAN request."""
        if not os.path.isfile(filename):
            raise ValueError(f"The provided filename {filename} doesn't exist.")

        print(f"Uploading {filename}...")
        out = self._run(
            "submit",
            *self.scanner_args(ArtifactType(atype)),
            "--scanner",
            self._scanner.value,
            str(filename),
        )

        # ugly, but not on me
        token = out[: -(len("Scan request submitted."))].strip()
        if not token:
            raise UploadError("no token obtained; check error logs.")
        return token

    def wait(
        self, token: str, timeout: Optional[int] = None, status: str = ProcessingStatus.success
    ):
        """Wait for `timeout` minutes for the remote SECSCAN generation to complete."""
        print(f"Awaiting {_crop_token(token)} to be ready")

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

    def download_report(self, token: Token, output_file: Optional[Union[str, Path]] = None):
        """Download SECSCAN report for the given token."""
        print(f"Downloading report for token: {token.cropped}")

        report = self._run("report", token=token)
        if not report:
            raise DownloadError("failed to download report, check error logs")

        # Save to file if output_file is specified
        if output_file:
            Path(output_file).write_text(report)
            print(f"secscan report saved to {output_file}")

        else:
            print(report)

    def query_status(self, token: str) -> ProcessingStatus:
        """Query the status of an SECSCAN request."""
        status_output = self._run("status", token=token)

        if status_output.startswith("Scan request is queued at position"):
            logger.info(f"{_crop_token(token)} status: {status_output}")
            return ProcessingStatus.pending

        processing_status = self._status_map.get(status_output, None)
        if processing_status is None:
            logger.error(
                f"Status call returned unexpected value; "
                f"taking it to mean secscan has failed. {status_output!r}"
            )
            return ProcessingStatus.failed
        return processing_status
