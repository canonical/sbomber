import os
from contextlib import contextmanager
from pathlib import Path
from typing import List, Dict
from unittest.mock import patch, MagicMock

import pytest
import yaml

from clients.client import ProcessingStatus
from clients.sbom import DEFAULT_SERVICE_URL
from sbomber import (
    DEFAULT_MANIFEST,
    DEFAULT_PACKAGE_DIR,
    prepare,
    DEFAULT_STATEFILE,
    submit,
    SBOMB_KEY,
    SECSCAN_KEY,
)


@pytest.fixture(autouse=True)
def project(tmp_path):
    os.chdir(tmp_path)
    return tmp_path


def mock_manifest(
    project: Path,
    artifacts: List[dict],
    generate=("sbom", "secscan"),
    prepared: bool = False,
    sboms_requests: Dict[str, str] = None,
    secscans_requests: Dict[str, str] = None,
):
    d = {
        "sbom-service-url": "https://sbom-request-test.canonical.com",
        "department": "charming_engineering",
        "email": "luca.bello@canonical.com",
        "team": "observability",
        "generate": generate,
        "artifacts": artifacts,
    }
    (project / DEFAULT_MANIFEST).write_text(yaml.safe_dump(d))

    if prepared:
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


@pytest.fixture(autouse=True)
def sbomber_get_mock(project: Path):
    mm = MagicMock()
    mm.return_value.status_code = 200
    mm.return_value.json.return_value = {"data": True, "message": "Chunk Found"}

    with patch("requests.get", mm):
        yield mm


@pytest.fixture(autouse=True)
def sbomber_post_mock(project: Path):
    def get_mm(url, *args, **kwargs):
        mm = MagicMock()
        mm.status_code = 200

        if url.endswith("/upload"):
            mm.json.return_value = {
                "data": {"artifactId": "this-is-a-testing-sbomber-token"}
            }
        return mm

    with patch("requests.post", side_effect=get_mm) as mm:
        yield mm


@pytest.fixture(autouse=True)
def secscanner_run_mock(project: Path):
    def get_mm(*args, **kwargs):
        command, *_ = args
        if command == "status":
            return "Scan has succeeded."
        elif command == "report":
            return "<some html>"
        elif command == "submit":
            return "this-is-a-testing-secscanner-token Scan request submitted."
        else:
            raise ValueError(command)

    with patch("clients.secscanner.Scanner._run", side_effect=get_mm) as mm:
        yield mm


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


def test_prepare_collect(project, sbomber_get_mock, sbomber_post_mock):
    mock_dev_env(project)
    prepare()

    assert not sbomber_get_mock.called
    assert not sbomber_post_mock.called

    for name, type in (
        ("foo", "charm"),
        ("bar", "rock"),
        ("baz", "snap"),
    ):
        assert (
            project / DEFAULT_PACKAGE_DIR / f"{name}.{type}"
        ).read_text() == f"Hello, I am a {type}."


def test_prepare_statefile(project, tmp_path, sbomber_get_mock, sbomber_post_mock):
    mock_dev_env(project)
    prepare()

    assert yaml.safe_load((project / DEFAULT_STATEFILE).read_text()) == {
        "artifacts": [
            {
                "name": name,
                "source": str(tmp_path / f"{name}.{type}"),
                "object": str(tmp_path / f"{name}.{type}"),
                "type": type,
            }
            for name, type in (
                ("foo", "charm"),
                ("bar", "rock"),
                ("baz", "snap"),
            )
        ],
        "department": "charming_engineering",
        "email": "luca.bello@canonical.com",
        "generate": ["sbom", "secscan"],
        "sbom-service-url": DEFAULT_SERVICE_URL,
        "team": "observability",
    }


def test_submit(
    project, tmp_path, sbomber_get_mock, sbomber_post_mock, secscanner_run_mock
):
    mock_dev_env(project, prepared=True)
    submit()
    assert sbomber_get_mock.called
    assert sbomber_post_mock.call_count == 6  # 1 chunk and 1 complete call each
    assert secscanner_run_mock.call_count == 3

    assert yaml.safe_load((project / DEFAULT_STATEFILE).read_text()) == {
        "artifacts": [
            {
                "name": name,
                "source": str(tmp_path / f"{name}.{type}"),
                "object": str(tmp_path / f"{name}.{type}"),
                SBOMB_KEY: {
                    "this-is-a-testing-sbomber-token": ProcessingStatus.pending.value
                },
                SECSCAN_KEY: {
                    "this-is-a-testing-secscanner-token": ProcessingStatus.pending.value
                },
                "type": type,
            }
            for name, type in (
                ("foo", "charm"),
                ("bar", "rock"),
                ("baz", "snap"),
            )
        ],
        "department": "charming_engineering",
        "email": "luca.bello@canonical.com",
        "generate": ["sbom", "secscan"],
        "sbom-service-url": DEFAULT_SERVICE_URL,
        "team": "observability",
    }
