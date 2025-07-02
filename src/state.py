"""Sbomber state classes."""

import json
import logging
from enum import Enum, StrEnum
from pathlib import Path
from typing import List, Optional, Tuple

import pydantic
import yaml

logger = logging.getLogger()


class ArtifactType(str, Enum):
    """ArtifactType."""

    charm = "charm"
    deb = "deb"
    rock = "rock"
    snap = "snap"
    wheel = "wheel"
    sdist = "sdist"

    @staticmethod
    def from_path(path: Path) -> "ArtifactType":
        """Instantiate from path."""
        if path.name.endswith(".charm"):
            return ArtifactType.charm
        if path.name.endswith(".deb"):
            return ArtifactType.deb
        if path.name.endswith(".rock"):
            return ArtifactType.rock
        if path.name.endswith(".snap"):
            return ArtifactType.snap
        if path.name.endswith(".whl"):
            return ArtifactType.wheel
        if path.name.endswith(".tar.gz"):
            return ArtifactType.sdist
        raise NotImplementedError(path.suffix)


class UbuntuRelease(StrEnum):
    """UbuntuRelease."""

    trusty = "14.04"
    xenial = "16.04"
    bionic = "18.04"
    focal = "20.04"
    jammy = "22.04"
    noble = "24.04"
    oracular = "24.10"
    plucky = "25.04"
    questing = "25.10"
    # TODO ??? = "26.04"


class ProcessingStep(str, Enum):
    """Processing steps.

    The user must prepare and submit.
    After that, they may poll and/or download any number of
    times, in whatever order they like, but they shouldn't probably submit/prepare again.
    - Preparing again should be harmless but pointless.
    - Submitting again might only have sense if there was a transient client error,
      but usually those don't go away by themselves.
    """

    prepare = "prepare"
    submit = "submit"
    process = "process"


class ProcessingStatus(str, Enum):
    """Valid statuses for each step."""

    not_started = "Not started"

    # only the 'process' step can be pending; the others can only fail, succeed or error.
    pending = "Pending"

    success = "Succeeded"
    failed = "Failed"

    error = "Error"


class CompressionType(StrEnum):
    """Compression."""

    gz = "gz"
    xz = "xz"
    zst = "zst"
    zip = "zip"


RETRYABLE_STATUSES = {
    ProcessingStatus.error,
    ProcessingStatus.failed,
    ProcessingStatus.not_started,
}


class _Client(pydantic.BaseModel):
    """_Client model."""

    pass


class SecScanClient(pydantic.BaseModel):
    """SecScanClient model."""

    scanner: str = "trivy"
    include_id_params: bool = False
    """Include the --ssdlc-* parameters in the secscan execution.

    When included, the artifacts must have a base, channel, and version defined.
    Scan results will be automatically transferred to a long-term SSDLC scan
    registry."""


class SBOMClient(pydantic.BaseModel):
    """SBOMClient model."""

    service_url: Optional[str] = None
    department: str
    email: str
    team: str


class _CurrentProcessingStatus(pydantic.BaseModel):
    """_CurrentProcessingStatus model."""

    def __str__(self):
        if not self.step:
            return "-no step-"
        return f"{self.step.value}/{self.status.value}"

    step: Optional[ProcessingStep] = None
    status: ProcessingStatus = ProcessingStatus.not_started
    token: Optional[str] = None  # only set when started


class Token(str):
    """Token."""

    @property
    def cropped(self):
        """Cropped."""
        return f"{self[:20]}[...]"


class Processing(pydantic.BaseModel):
    """Processing model."""

    secscan: _CurrentProcessingStatus = _CurrentProcessingStatus()
    sbom: _CurrentProcessingStatus = _CurrentProcessingStatus()

    @property
    def __iter__(self):  # type: ignore[reportIncompatibleMethodOverride]
        """Iterate through all statuses."""
        for val in (self.secscan, self.sbom):
            yield val

    def get_status(self, client_name: str) -> _CurrentProcessingStatus:
        """Get the current processing status for this client."""
        return getattr(self, client_name)

    def get_token(self, client_name: str) -> Optional[Token]:
        """Get the token assigned by this client."""
        current_status = self.get_status(client_name)
        if not current_status:
            return None
        return Token(current_status.token)

    def check_step(self, client_name: str, *status: Tuple[ProcessingStep, ProcessingStatus]):
        """Verify the state transition."""
        current_status = self.get_status(client_name)
        if not current_status:
            raise ValueError("no current status")
        if (current_status.step, current_status.status) not in status:
            return False
        return True

    @property
    def started(self) -> bool:
        """Whether processing has started or not."""
        return bool(getattr(self.secscan, "token", None) or getattr(self.sbom, "token", None))


class Artifact(pydantic.BaseModel):
    """Artifact model."""

    name: str
    type: ArtifactType
    source: Optional[str] = None
    clients: Optional[List[str]] = None  # list of client names enabled for this artifact
    version: Optional[str] = None  # for charms and snaps, this maps to 'revision'
    base: Optional[str] = None
    compression: Optional[CompressionType] = None

    # specific for charms for sbom, generic for secscan
    channel: Optional[str] = None

    # specific for OCI images
    image: Optional[str] = None

    # specific for debs
    package: Optional[str] = None
    arch: Optional[str] = None  # also for wheels
    variant: Optional[str] = None
    pocket: Optional[str] = None  # todo: is this mandatory for debs?
    ppa: Optional[str] = None

    # only set in statefile:
    # path in pkg_dir
    object: Optional[str] = None
    # mapping from processing steps to states
    processing: Processing = Processing()

    @pydantic.model_validator(mode="after")
    def _check_args(self):
        if self.type == "deb":
            if any(x is None for x in [self.variant, self.arch, self.base]):
                raise ValueError("variant, arch and base are required for deb artifacts.")
        return self

    @property
    def processing_statuses(self):
        """All enabled processing statuses."""
        if clients := self.clients:
            for client_name in clients:
                yield self.processing.get_status(client_name)
        else:
            yield self.processing.sbom
            yield self.processing.secscan


class _Clients(pydantic.BaseModel):
    """_Clients."""

    sbom: Optional[SBOMClient] = None
    secscan: Optional[SecScanClient] = None

    def __iter__(self):
        """__iter__."""
        yield "sbom", self.sbom
        yield "secscan", self.secscan


class Manifest(pydantic.BaseModel):
    """Manifest."""

    clients: _Clients
    artifacts: List[Artifact]

    @classmethod
    def load(cls, file: Path) -> "Manifest":
        """Load from file."""
        logger.debug(f"loading {cls.__name__} from {file}")
        return cls.model_validate(yaml.safe_load(file.read_text()))

    def dump(self, file: Path):
        """Dump to file."""
        logger.debug(f"dumping {type(self).__name__} to {file}")

        # horrible, but we want to store yaml, not json.
        return file.write_text(
            yaml.safe_dump(json.loads(self.model_dump_json(exclude_defaults=True)))
        )


class Statefile(Manifest):
    """Statefile."""
