import contextlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sbomber import DEFAULT_PACKAGE_DIR


@pytest.fixture(autouse=True)
def project(tmp_path):
    os.chdir(tmp_path)
    return tmp_path


@pytest.fixture(autouse=True)
def sbomber_get_mock(project: Path):
    def _get_mock(url: str, *_, **__):
        if "artifacts/sbom" in url:
            # this is a download_report request
            mm = MagicMock()
            mm.status_code = 200
            mm.text = "this is a sbom"

        elif "artifacts/upload/chunk" in url:
            mm = MagicMock()
            mm.status_code = 200
            mm.json.return_value = {"data": True, "message": "Chunk Found"}

        elif "artifacts/status" in url:
            # this is a status query request
            mm = MagicMock()
            mm.status_code = 200
            mm.json.return_value = {"status": "Pending"}

        else:
            raise NotImplementedError(url)

        return mm

    with patch("requests.get", side_effect=_get_mock) as mm:
        yield mm


@contextlib.contextmanager
def mock_charm_download(
    project: Path,
    charm_name: str,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
):
    mm = MagicMock()
    mm.return_value.stdout = stdout
    mm.return_value.stderr = (
        stderr
        or f"""
        Fetching charm "somecharm" revision XXX
        Install the "somecharm" charm with:
        juju deploy ./{charm_name}
    """
    )
    mm.return_value.returncode = returncode
    with patch("subprocess.run", mm):
        package_dir = project / DEFAULT_PACKAGE_DIR
        package_dir.mkdir(exist_ok=True)
        (package_dir / charm_name).write_text("ceci est une charm")
        yield mm


@pytest.fixture(autouse=True)
def sbomber_post_mock(project: Path):
    def get_mm(url, *args, **kwargs):
        mm = MagicMock()
        mm.status_code = 200

        if "/complete/" in url:
            mm.json.return_value = {"message": "Upload completed successfully"}

        elif url.endswith("/upload"):
            mm.json.return_value = {"data": {"artifactId": "sbom-token"}}
        return mm

    with patch("requests.post", side_effect=get_mm) as mm:
        yield mm


@pytest.fixture(autouse=True)
def secscanner_run_mock(project: Path):
    def get_mm(*args, **kwargs):
        command, *_ = args
        if command == "status":
            return "Scan has succeeded."
        if command == "report":
            return "<some html>"
        if command == "submit":
            return "secscan-token Scan request submitted."
        raise ValueError(command)

    with patch("clients.secscanner.Scanner._verify_client_installed"):
        with patch("clients.secscanner.Scanner._run", side_effect=get_mm) as mm:
            yield mm
