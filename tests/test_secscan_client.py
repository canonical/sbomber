from unittest.mock import patch

import pytest

from clients.client import DownloadError
from clients.secscanner import Scanner
from state import Artifact, ArtifactType, ProcessingStatus, SSDLCParams, Token, UbuntuRelease


def artifact_deb():
    return Artifact(
        name="testpkg",
        package="testpkg_1.0_amd64.deb",
        version="1.0",
        variant="main",
        base="jammy",
        arch="amd64",
        pocket="updates",
        channel="stable",
        type=ArtifactType.deb,
        ssdlc_params=SSDLCParams(
            name="test-product",
            version="1.0",
            channel="stable",
            cycle=UbuntuRelease.jammy.value,
        ),
    )


def artifact_snap():
    return Artifact(
        name="testsnap",
        version="2.0",
        base="questing",
        channel="latest/stable",
        type=ArtifactType.snap,
        ssdlc_params=SSDLCParams(
            name="test-product",
            version="2.0",
            channel="stable",
            cycle=UbuntuRelease.questing.value,
        ),
    )


def artifact_rock():
    return Artifact(
        name="testsrock",
        version="2.0",
        base="questing",
        channel="latest/stable",
        type=ArtifactType.rock,
        ssdlc_params=SSDLCParams(
            name="test-product",
            version="2.0",
            channel="stable",
            cycle=UbuntuRelease.questing.value,
        ),
    )


def artifact_charm():
    return Artifact(
        name="testcharm",
        version="2.0",
        base="questing",
        channel="latest/stable",
        type=ArtifactType.charm,
        ssdlc_params=SSDLCParams(
            name="test-product",
            version="2.0",
            channel="stable",
            cycle=UbuntuRelease.questing.value,
        ),
    )


@pytest.mark.parametrize("ppa", [None, "example-ppa"])
def test_scanner_args_deb(ppa):
    artifact = artifact_deb()
    artifact.ppa = ppa
    scanner = Scanner()
    args = scanner.scanner_args(artifact)
    assert "--format" in args and "deb" in args
    assert "--type" in args and "package" in args
    assert "--base" in args and artifact.base in args
    assert "--base-arch" in args and artifact.arch in args
    assert "--base-pocket" in args and artifact.pocket in args
    if ppa:
        assert "--base-ppa" in args and artifact.ppa in args


@pytest.mark.parametrize(
    "artifact,format,artifact_type",
    [
        (artifact_charm(), "charm", "package"),
        (artifact_rock(), "oci", "container-image"),
        (artifact_snap(), "snap", "package"),
    ],
)
def test_scanner_args_simple(artifact: Artifact, format: str, artifact_type: str):
    scanner = Scanner()
    args = scanner.scanner_args(artifact)
    assert "--format" in args and format in args
    assert "--type" in args and artifact_type in args


def test_scanner_args_sssdlc_params():
    artifact = artifact_snap()
    scanner = Scanner()
    args = scanner.scanner_args(artifact)
    assert "--ssdlc-product-name" in args
    assert artifact.ssdlc_params.name in args
    assert "--ssdlc-product-version" in args
    assert artifact.ssdlc_params.version in args
    assert "--ssdlc-product-channel" in args
    assert artifact.ssdlc_params.channel in args
    assert "--ssdlc-cycle" in args
    assert artifact.ssdlc_params.cycle in args


@pytest.mark.parametrize(
    "params",
    [
        {"version": "1.0", "channel": "stable", "cycle": "25.10"},
        {"name": "test-product", "channel": "stable", "cycle": "25.10"},
        {"name": "test-product", "version": "1.0", "cycle": "25.10"},
        {"name": "test-product", "version": "1.0", "channel": "stable"},
    ],
)
def test_scanner_args_ssdlc_params_missing_fields(params: dict[str, str]):
    with pytest.raises(ValueError):
        Artifact(
            name="bad-artifact",
            type=ArtifactType.snap,
            ssdlc_params=SSDLCParams(**params),
        )


# The _run patches here override the ones from secscanner_run_mock.
@patch.object(Scanner, "_run")
def test_download_report_success(mock_run, tmp_path):
    scanner = Scanner()
    token = Token("sometoken")
    mock_run.return_value = "report content"
    output_file = tmp_path / "report.txt"
    scanner.download_report(token, output_file)
    assert output_file.read_text() == "report content"


@patch.object(Scanner, "_run")
def test_download_report_failure(mock_run):
    scanner = Scanner()
    token = Token("sometoken")
    mock_run.return_value = None
    with pytest.raises(DownloadError):
        scanner.download_report(token)


@patch.object(Scanner, "_run")
def test_query_status_pending(mock_run):
    scanner = Scanner()
    mock_run.return_value = "Scan request is queued at position 2"
    status = scanner.query_status("sometoken")
    assert mock_run.call_args[0][0] == "status"
    assert mock_run.call_args.kwargs["token"] == "sometoken"
    assert status == ProcessingStatus.pending


@patch.object(Scanner, "_run")
def test_query_status_success(mock_run):
    scanner = Scanner()
    mock_run.return_value = "Scan has succeeded."
    status = scanner.query_status("sometoken")
    assert mock_run.call_args[0][0] == "status"
    assert mock_run.call_args.kwargs["token"] == "sometoken"
    assert status == ProcessingStatus.success


@patch.object(Scanner, "_run")
def test_query_status_failed(mock_run):
    scanner = Scanner()
    mock_run.return_value = "unexpected status"
    status = scanner.query_status("sometoken")
    assert mock_run.call_args[0][0] == "status"
    assert mock_run.call_args.kwargs["token"] == "sometoken"
    assert status == ProcessingStatus.failed
