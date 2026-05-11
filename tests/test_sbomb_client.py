from unittest.mock import MagicMock, patch

import yaml

from sbomber import (
    DEFAULT_PACKAGE_DIR,
    DEFAULT_REPORTS_DIR,
    DEFAULT_STATEFILE,
    download,
    poll,
    prepare,
    submit,
)
from state import ProcessingStatus, ProcessingStep
from tests.conftest import mock_package_download
from tests.helpers import mock_dev_env, mock_manifest


def test_prepare_collect(project, sbomber_get_mock, sbomber_post_mock):
    mock_dev_env(project)

    with mock_package_download(project, "foo_r299.charm"):
        prepare()

    assert not sbomber_get_mock.called
    assert not sbomber_post_mock.called

    for name, type in (
        ("bar", "rock"),
        ("baz", "snap"),
    ):
        assert (
            project / DEFAULT_PACKAGE_DIR / f"{name}.{type}"
        ).read_text() == f"Hello, I am a {type}."


def test_prepare_statefile(project, tmp_path, sbomber_get_mock, sbomber_post_mock):
    mock_dev_env(project)
    with mock_package_download(project, "foo_r299.charm"):
        prepare()

    assert yaml.safe_load((project / DEFAULT_STATEFILE).read_text()) == {
        "artifacts": [
            {
                "name": "foo",
                "object": "foo_r299.charm",
                "type": "charm",
                "version": "299",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "bar",
                "object": str(tmp_path / "bar.rock"),
                "source": str(tmp_path / "bar.rock"),
                "type": "rock",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "baz",
                "object": str(tmp_path / "baz.snap"),
                "source": str(tmp_path / "baz.snap"),
                "type": "snap",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "qux",
                "object": "foo_r299.charm-1.0.0-py3-none-any.whl",
                "type": "wheel",
                "version": "1.0.0",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "quux",
                "object": "foo_r299.charm-1.0.0.tar.gz",
                "version": "1.0.0",
                "type": "sdist",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
        ],
        "clients": {
            "sbom": {
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "service_url": "https://sbom-request.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }


def test_prepare(project, tmp_path):
    mock_dev_env(project)
    with mock_package_download(project, "foo_r299.charm") as mm:
        prepare()

    assert mm.call_count == 3
    # charm, wheel, sdist artifacts are remote; the rest are local

    assert yaml.safe_load((project / DEFAULT_STATEFILE).read_text()) == {
        "artifacts": [
            {
                "name": "foo",
                "object": "foo_r299.charm",
                "type": "charm",
                "version": "299",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "bar",
                "object": str(tmp_path / "bar.rock"),
                "source": str(tmp_path / "bar.rock"),
                "type": "rock",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "baz",
                "object": str(tmp_path / "baz.snap"),
                "source": str(tmp_path / "baz.snap"),
                "type": "snap",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "qux",
                "object": "foo_r299.charm-1.0.0-py3-none-any.whl",
                "type": "wheel",
                "version": "1.0.0",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "quux",
                "object": "foo_r299.charm-1.0.0.tar.gz",
                "type": "sdist",
                "version": "1.0.0",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
        ],
        "clients": {
            "sbom": {
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "service_url": "https://sbom-request.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }


def test_submit(project, tmp_path, sbomber_get_mock, sbomber_post_mock, secscanner_run_mock):
    mock_dev_env(project, step=ProcessingStep.prepare)
    submit()

    assert secscanner_run_mock.call_count == 5
    # 1 register-artifact, 1 chunk upload and 1 complete call per artifact
    assert sbomber_post_mock.call_count == 15

    assert yaml.safe_load((project / DEFAULT_STATEFILE).read_text()) == {
        "artifacts": [
            {
                "name": "foo",
                "object": str(tmp_path / "pkgs" / "foo.charm"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "secscan-token",
                    },
                },
                "type": "charm",
            },
            {
                "name": "bar",
                "object": str(tmp_path / "pkgs" / "bar.rock"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "secscan-token",
                    },
                },
                "source": str(tmp_path / "bar.rock"),
                "type": "rock",
            },
            {
                "name": "baz",
                "object": str(tmp_path / "pkgs" / "baz.snap"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "secscan-token",
                    },
                },
                "source": str(tmp_path / "baz.snap"),
                "type": "snap",
            },
            {
                "name": "qux",
                "object": str(tmp_path / "pkgs" / "qux-1.0.0-py3-none-any.whl"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "secscan-token",
                    },
                },
                "type": "wheel",
            },
            {
                "name": "quux",
                "object": str(tmp_path / "pkgs" / "quux.sdist"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "secscan-token",
                    },
                },
                "type": "sdist",
            },
        ],
        "clients": {
            "sbom": {
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "service_url": "https://sbom-request.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }


def test_poll(project, tmp_path, sbomber_get_mock, secscanner_run_mock):
    mock_dev_env(project, step=ProcessingStep.submit, status=ProcessingStatus.pending)
    poll()

    assert sbomber_get_mock.call_count == 5
    assert secscanner_run_mock.call_count == 5

    # sboms are still in pending, secscans updated to success
    assert yaml.safe_load((project / DEFAULT_STATEFILE).read_text()) == {
        "artifacts": [
            {
                "name": "foo",
                "object": str(tmp_path / "pkgs" / "foo.charm"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.success.value,
                        "token": "secscan-token",
                    },
                },
                "type": "charm",
            },
            {
                "name": "bar",
                "object": str(tmp_path / "pkgs" / "bar.rock"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.success.value,
                        "token": "secscan-token",
                    },
                },
                "source": str(tmp_path / "bar.rock"),
                "type": "rock",
            },
            {
                "name": "baz",
                "object": str(tmp_path / "pkgs" / "baz.snap"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.success.value,
                        "token": "secscan-token",
                    },
                },
                "source": str(tmp_path / "baz.snap"),
                "type": "snap",
            },
            {
                "name": "qux",
                "object": str(tmp_path / "pkgs" / "qux-1.0.0-py3-none-any.whl"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.success.value,
                        "token": "secscan-token",
                    },
                },
                "type": "wheel",
            },
            {
                "name": "quux",
                "object": str(tmp_path / "pkgs" / "quux.sdist"),
                "processing": {
                    "sbom": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.pending.value,
                        "token": "sbom-token",
                    },
                    "secscan": {
                        "step": ProcessingStep.submit.value,
                        "status": ProcessingStatus.success.value,
                        "token": "secscan-token",
                    },
                },
                "type": "sdist",
            },
        ],
        "clients": {
            "sbom": {
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "service_url": "https://sbom-request.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }


def test_prepare_charm_name_override(project, sbomber_get_mock, sbomber_post_mock):
    """When charm: is set, juju downloads using that store name, not the display name."""
    artifacts = [
        {
            "name": "alertmanager-k8s-2",
            "charm": "alertmanager-k8s",
            "channel": "2/edge",
            "type": "charm",
        }
    ]
    mock_manifest(project, artifacts)

    with mock_package_download(project, "alertmanager-k8s_r299.charm") as mm:
        prepare()

    # juju was called with the store charm name, not the display name
    juju_cmd = mm.call_args_list[0].args[0]
    assert juju_cmd[:3] == ["juju", "download", "alertmanager-k8s"]
    assert "alertmanager-k8s-2" not in juju_cmd

    # statefile preserves the display name and the charm override
    sf = yaml.safe_load((project / DEFAULT_STATEFILE).read_text())
    assert sf["artifacts"][0]["name"] == "alertmanager-k8s-2"
    assert sf["artifacts"][0]["charm"] == "alertmanager-k8s"
    assert sf["artifacts"][0]["processing"]["sbom"]["status"] == ProcessingStatus.success.value


def test_prepare_snap_name_override(project, sbomber_get_mock, sbomber_post_mock):
    """When snap: is set, snap downloads using that store name, not the display name."""
    artifacts = [
        {
            "name": "jhack-latest",
            "snap": "jhack",
            "channel": "latest/stable",
            "type": "snap",
        }
    ]
    mock_manifest(project, artifacts)

    snap_filename = "jhack_445.snap"

    def subprocess_side_effect(cmd, *args, **kwargs):
        mock = MagicMock()
        mock.returncode = 0
        mock.stderr = ""
        if cmd[0] == "snap":
            mock.stdout = f"snap install {snap_filename}"
            (project / snap_filename).write_text("ceci est une snap")
        return mock

    with patch("subprocess.run", side_effect=subprocess_side_effect) as mm:
        prepare()

    # snap was called with the store snap name, not the display name
    snap_cmd = mm.call_args_list[0].args[0]
    assert snap_cmd[:3] == ["snap", "download", "jhack"]
    assert "jhack-latest" not in snap_cmd

    # statefile preserves the display name and the snap override
    sf = yaml.safe_load((project / DEFAULT_STATEFILE).read_text())
    assert sf["artifacts"][0]["name"] == "jhack-latest"
    assert sf["artifacts"][0]["snap"] == "jhack"
    assert sf["artifacts"][0]["processing"]["sbom"]["status"] == ProcessingStatus.success.value


def test_prepare_multi_channel_no_dedup(project, sbomber_get_mock, sbomber_post_mock):
    """Two charms with the same name but different channels are both prepared."""
    artifacts = [
        {"name": "alertmanager-k8s", "channel": "2/edge", "type": "charm"},
        {"name": "alertmanager-k8s", "channel": "dev/edge", "type": "charm"},
    ]
    mock_manifest(project, artifacts)

    with mock_package_download(project, "alertmanager-k8s_r100.charm"):
        prepare()

    sf = yaml.safe_load((project / DEFAULT_STATEFILE).read_text())
    assert len(sf["artifacts"]) == 2
    assert {a.get("channel") for a in sf["artifacts"]} == {"2/edge", "dev/edge"}
    for a in sf["artifacts"]:
        assert a["processing"]["sbom"]["status"] == ProcessingStatus.success.value
        assert a["processing"]["secscan"]["status"] == ProcessingStatus.success.value


def test_download_filename_includes_channel(project, sbomber_get_mock, secscanner_run_mock):
    """Report filenames include the channel slug when an artifact has a channel set."""
    artifacts = [{"name": "alertmanager-k8s", "type": "charm", "channel": "2/edge"}]
    mock_manifest(project, artifacts, step=ProcessingStep.submit, status=ProcessingStatus.success)

    download()

    reports_dir = project / DEFAULT_REPORTS_DIR
    assert (reports_dir / "alertmanager-k8s-2-edge-charm.sbom.json").exists()
    assert (reports_dir / "alertmanager-k8s-2-edge-charm.secscan.html").exists()
