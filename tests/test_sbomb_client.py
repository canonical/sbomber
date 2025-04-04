import yaml

from sbomber import (
    DEFAULT_PACKAGE_DIR,
    prepare,
    DEFAULT_STATEFILE,
    submit,
    poll,
)
from state import ProcessingStep, ProcessingStatus
from tests.conftest import mock_charm_download
from tests.helpers import mock_dev_env


def test_prepare_collect(project, sbomber_get_mock, sbomber_post_mock):
    mock_dev_env(project)

    with mock_charm_download(project, "parca-k8s_r299.charm"):
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
    with mock_charm_download(project, "parca-k8s_r299.charm"):
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
        ],
        "clients": {
            "sbom": {
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "service_url": "https://sbom-request-test.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }


def test_prepare(project, tmp_path):
    mock_dev_env(project)
    with mock_charm_download(project, "parca-k8s_r299.charm") as mm:
        prepare()

    assert mm.call_count == 1
    # charm artifact is remote; the rest are local

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
        ],
        "clients": {
            "sbom": {
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "service_url": "https://sbom-request-test.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }


def test_submit(
    project, tmp_path, sbomber_get_mock, sbomber_post_mock, secscanner_run_mock
):
    mock_dev_env(project, step=ProcessingStep.prepare)
    submit()

    assert secscanner_run_mock.call_count == 3
    assert sbomber_post_mock.call_count == 6  # 1 chunk and 1 complete call each

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
        ],
        "clients": {
            "sbom": {
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "service_url": "https://sbom-request-test.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }


def test_poll(project, tmp_path, sbomber_get_mock, secscanner_run_mock):
    mock_dev_env(project, step=ProcessingStep.submit, status=ProcessingStatus.pending)
    poll()

    assert sbomber_get_mock.call_count == 3
    assert secscanner_run_mock.call_count == 3

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
        ],
        "clients": {
            "sbom": {
                "department": "charm_engineering",
                "email": "luca.bello@canonical.com",
                "service_url": "https://sbom-request-test.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }
