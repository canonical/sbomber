"""Client base class and shared enums."""

import abc
from pathlib import Path
from typing import Optional, Union

from state import Artifact, ArtifactType, ProcessingStatus, Token


class WaitError(RuntimeError):
    """Raised by a Client if a request for updates fails."""


class DownloadError(RuntimeError):
    """Raised by a Client if a downloading a sbom fails."""


class UploadError(RuntimeError):
    """Raised by a Client if uploading an artifact fails."""


class Client(abc.ABC):
    """Generic Client ABC."""

    def run(
        self,
        filename: Union[str, Path],
        atype: str,
        timeout: int = 15,
        version: Optional[Union[int, str]] = None,
        output_file: Optional[Path] = None,
    ):
        """End-to-end, blocking request flow for a single artifact."""
        kwargs = {
            filename: filename,
            atype: ArtifactType(atype),
        }
        if version is not None:
            kwargs["version"] = version

        token = self.submit(**kwargs)
        self.wait(token, timeout=timeout)
        self.download_report(token, output_file=output_file)

    @abc.abstractmethod
    def submit(
        self,
        filename: Union[str, Path],
        artifact: Artifact,
    ) -> Token:
        """Submit artifact and return unique token."""
        ...

    @abc.abstractmethod
    def query_status(self, token: str) -> ProcessingStatus:
        """Get the current status from the client backend."""
        ...

    @abc.abstractmethod
    def wait(
        self,
        token: str,
        timeout: Optional[int] = None,
        status: ProcessingStatus = ProcessingStatus.success,
    ):
        """Wait until status for the given unique token has converged."""
        ...

    @abc.abstractmethod
    def download_report(self, token: Token, output_file: Union[str, Path, None] = None):
        """Download report for the given unique token."""
        ...
