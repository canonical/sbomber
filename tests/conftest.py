import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def project(tmp_path):
    os.chdir(tmp_path)
    return tmp_path


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

    with patch("clients.secscanner.Scanner._verify_client_installed"):
        with patch("clients.secscanner.Scanner._run", side_effect=get_mm) as mm:
            yield mm
