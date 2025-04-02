from contextlib import contextmanager
from pathlib import Path
from typing import List, Dict

import yaml

from sbomber import (
    DEFAULT_MANIFEST,
    DEFAULT_STATEFILE,
    DEFAULT_PACKAGE_DIR,
    STATE_METADATA_KEY,
)


def mock_manifest(
    project: Path,
    artifacts: List[dict],
    prepared: bool = False,
    sboms_requests: Dict[str, str] = None,
    secscans_requests: Dict[str, str] = None,
):
    d = {
        "clients": {
            "sbom": {
                "sbom-service-url": "https://sbom-request-test.canonical.com",
                "department": "charming_engineering",
                "email": "luca.bello@canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
        "artifacts": artifacts,
    }
    (project / DEFAULT_MANIFEST).write_text(yaml.safe_dump(d))

    if prepared:
        d[STATE_METADATA_KEY] = ["prepared"]
        for a in artifacts:
            a["object"] = a["source"]
            if sboms_requests:
                a["sbom"]: sboms_requests
            if secscans_requests:
                a["secscan"]: secscans_requests
        (project / DEFAULT_STATEFILE).write_text(yaml.safe_dump(d))


@contextmanager
def artifact(project: Path, name: str, a: str):
    (project / DEFAULT_PACKAGE_DIR / name).write_text(a)


def mock_dev_env(project: Path, prepared=False):
    """Setup a temporary folder with some stuff pretending to be a valid sbomber project."""
    artifacts = []
    for name, type in (
        ("foo", "charm"),
        ("bar", "rock"),
        ("baz", "snap"),
    ):
        pkg = f"{name}.{type}"
        src = project / pkg
        content = f"Hello, I am a {type}."
        src.write_text(content)
        if prepared:
            (project / DEFAULT_PACKAGE_DIR).mkdir(exist_ok=True)
            (project / DEFAULT_PACKAGE_DIR / pkg).write_text(content)

        artifacts.append(
            {
                "name": name,
                "source": str(src),
                "type": type,
            }
        )
    mock_manifest(project, artifacts, prepared=prepared)
