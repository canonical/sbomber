from unittest.mock import MagicMock, patch

from pathlib import PosixPath

from sbomber import _detect_version
from state import Artifact, ArtifactType


def test_detect_version_charm():
    artifact = Artifact(name="parca-k8s", type=ArtifactType.charm)
    assert _detect_version(artifact, "parca-k8s_r363.charm") == "363"


def test_detect_version_deb():
    artifact = Artifact(
        name="cowsay", type=ArtifactType.deb, variant="universe", arch="amd64", base="jammy"
    )
    mock_output = "Package: cowsay\nVersion: 3.03+dfsg2-8\nPriority: optional"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_output)
        assert _detect_version(artifact, "cowsay.deb") == "3.03+dfsg2-8"
        mock_run.assert_called_with(
            ["dpkg-deb", "-I", PosixPath("pkgs/cowsay.deb")], capture_output=True, text=True, check=True
        )


def test_detect_version_rock():
    artifact = Artifact(name="myrock", type=ArtifactType.rock)
    assert _detect_version(artifact, "myrock_1.2.3.rock") is None


def test_detect_version_snap():
    artifact = Artifact(name="concierge", type=ArtifactType.snap)
    assert _detect_version(artifact, "concierge_40.snap") == "40"


def test_detect_version_sdist():
    artifact = Artifact(name="ops_scenario", type=ArtifactType.sdist)
    assert _detect_version(artifact, "ops_scenario-8.0.0.tar.gz") == "8.0.0"


def test_detect_version_wheel():
    artifact = Artifact(name="ops_scenario", type=ArtifactType.wheel)
    assert _detect_version(artifact, "ops_scenario-8.0.0-py3-none-any.whl") == "8.0.0"
