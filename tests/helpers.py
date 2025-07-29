from contextlib import contextmanager
from pathlib import Path
from typing import List

from sbomber import (
    DEFAULT_MANIFEST,
    DEFAULT_PACKAGE_DIR,
    DEFAULT_STATEFILE,
)
from state import Manifest, ProcessingStatus, ProcessingStep, Statefile


def mock_manifest(
    project: Path,
    artifacts: List[dict],
    statefile: dict = None,
    step: ProcessingStep = None,
    status: ProcessingStatus = None,
):
    clients = (
        statefile["clients"]
        if statefile
        else {
            "sbom": {
                "service_url": "https://sbom-request.canonical.com",
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "team": "observability",
            },
            "secscan": {},
        }
    )
    d = {
        "clients": clients,
        "artifacts": artifacts,
    }
    Manifest(**d).dump(project / DEFAULT_MANIFEST)

    if step:

        def _status(client):
            out = {
                "status": status.value,
                "step": step.value,
            }
            if step is not ProcessingStep.prepare.value:
                out["token"] = f"{client}-token"
            return out

        if not statefile:
            for artifact in artifacts:
                artifact["processing"] = {
                    "sbom": _status("sbom"),
                    "secscan": _status("secscan"),
                }
        Statefile(**d).dump(project / DEFAULT_STATEFILE)


@contextmanager
def artifact(project: Path, name: str, a: str):
    (project / DEFAULT_PACKAGE_DIR / name).write_text(a)


def mock_dev_env(
    project: Path,
    statefile=None,
    step: ProcessingStep = None,
    status: ProcessingStatus = ProcessingStatus.success,
):
    """Setup a temporary folder with some stuff pretending to be a valid sbomber project."""

    def _mock_artifact(artifact, local: bool = True, globbed: bool | None = None):
        name, type = artifact["name"], artifact["type"]
        if type == "wheel":
            pkg = f"{name}-1.0.0-py3-none-any.whl"
        else:
            pkg = f"{name}.{type}"
        content = f"Hello, I am a {type}."
        if local:
            src = project / pkg
            src.write_text(content)
            if globbed:
                artifact["source"] = str(src.parent)
                artifact["source_glob"] = f"*.{type}"
            else:
                artifact["source"] = str(src)

        if step:
            (project / DEFAULT_PACKAGE_DIR).mkdir(exist_ok=True)

            obj = project / DEFAULT_PACKAGE_DIR / pkg
            artifact["object"] = str(obj)
            obj.write_text(content)

    artifacts = (
        statefile["artifacts"]
        if statefile
        else [
            {
                "name": name,
                "type": type,
            }
            for name, type in (
                ("foo", "charm"),
                ("bar", "rock"),
                ("baz", "snap"),
                ("qux", "wheel"),
                ("quux", "sdist"),
            )
        ]
    )

    for artifact, local, globbed in zip(
        artifacts, (False, True, True, False, False), (None, False, True, None, None)
    ):
        _mock_artifact(artifact, local=local, globbed=globbed)
    mock_manifest(project, artifacts, statefile=statefile, step=step, status=status)
