import abc
from enum import Enum
from pathlib import Path
from typing import Union, Optional


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


class Client(abc.ABC):
    def run(
            self,
            filename: Union[str, Path],
            atype: str,
            timeout: int = 15,
            version: Optional[Union[int, str]] = None
    ):
        """End-to-end  request flow."""
        kwargs = {
            filename: filename,
            atype: ArtifactType(atype),
        }
        if version is not None:
            kwargs['version'] = version

        token = self.submit(**kwargs)
        self.wait(token, timeout=timeout)
        self.download_report(token)

    @abc.abstractmethod
    def submit(self, filename: Union[str, Path], atype: Union[str, ArtifactType],
               version: Optional[Union[int, str]] = None) -> str: ...

    @abc.abstractmethod
    def wait(self, token: str, timeout: int = None, status: str = ProcessingStatus.success): ...

    @abc.abstractmethod
    def download_report(self, token: str, output_file: Union[str, Path] = None): ...
