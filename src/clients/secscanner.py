"""Security scanner client."""

import logging
import os
import subprocess
from enum import Enum
from pathlib import Path
from typing import Optional, Union

import tenacity

from clients.client import ArtifactType, Client, ProcessingStatus

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
        if not subprocess.run(["which", self.CLIENT_NAME]).returncode == 0:
            raise RuntimeError(f"you must install {self.CLIENT_NAME}")

        self._scanner = scanner

    def _run(self, *cmd: str, token: Optional[str] = None):
        cmd = [self.CLIENT_NAME, *cmd]
        proc = subprocess.run(cmd, text=True, capture_output=True, input=token)
        if proc.stderr:
            logger.error(proc.stderr)
        return proc.stdout

    def submit(
        self, filename: Union[str, Path], atype: str, version: Optional[Union[int, str]] = None
    ) -> str:
        """Submit a SECSCAN request."""
        if not os.path.isfile(filename):
            raise ValueError(f"The provided filename {filename} doesn't exist.")

        print(f"Uploading {filename}...")
        out = self._run(
            "submit", *ArtifactType(atype).scanner_args, "--scanner", self._scanner.value, filename
        )

        # ugly, but not on me
        return out[: -(len("Scan request submitted.") + 1)].strip()

    def wait(self, token: str, timeout: int = None, status: str = ProcessingStatus.success):
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

    def download_report(self, token: str, output_file: Union[str, Path] = None):
        """Download SECSCAN report for the given token."""
        print(f"Downloading report for token: {_crop_token(token)}")

        report = self._run("report", token=token)

        # Save to file if output_file is specified
        if output_file:
            Path(output_file).write_text(report)
            print(f"secscan report saved to {output_file}")

        else:
            print(report)

    def query_status(self, token: str) -> ProcessingStatus:
        """Query the status of an SECSCAN request."""
        return self._status_map.get(self._run("status", token=token), ProcessingStatus.failed)
