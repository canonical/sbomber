import yaml

from sbomber import (
    DEFAULT_PACKAGE_DIR,
    DEFAULT_STATEFILE,
    poll,
    prepare,
    submit,
)
from state import ProcessingStatus, ProcessingStep
from tests.conftest import mock_package_download
from tests.helpers import mock_dev_env


def test_prepare_collect(project, sbomber_get_mock, sbomber_post_mock):
    mock_dev_env(project)

    with mock_package_download(project, "parca-k8s_r299.charm"):
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
    with mock_package_download(project, "parca-k8s_r299.charm"):
        prepare()

    assert yaml.safe_load((project / DEFAULT_STATEFILE).read_text()) == {
        "artifacts": [
            {
                "name": "foo",
                "object": "parca-k8s_r299.charm",
                "type": "charm",
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
                "object": "parca-k8s_r299.charm-1.0.0-py3-none-any.whl",
                "type": "wheel",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "quux",
                "object": "parca-k8s_r299.charm-1.0.0.tar.gz",
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
    with mock_package_download(project, "parca-k8s_r299.charm") as mm:
        prepare()

    assert mm.call_count == 3
    # charm, wheel, sdist artifacts are remote; the rest are local

    assert yaml.safe_load((project / DEFAULT_STATEFILE).read_text()) == {
        "artifacts": [
            {
                "name": "foo",
                "object": "parca-k8s_r299.charm",
                "type": "charm",
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
                "object": "parca-k8s_r299.charm-1.0.0-py3-none-any.whl",
                "type": "wheel",
                "processing": {
                    "sbom": {"step": "prepare", "status": "Succeeded"},
                    "secscan": {"step": "prepare", "status": "Succeeded"},
                },
            },
            {
                "name": "quux",
                "object": "parca-k8s_r299.charm-1.0.0.tar.gz",
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
                "object": str(tmp_path / "pkgs" / "qux.wheel"),
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
                "object": str(tmp_path / "pkgs" / "qux.wheel"),
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
