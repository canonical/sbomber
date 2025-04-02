import yaml

from clients.client import ProcessingStatus
from sbomber import (
    DEFAULT_PACKAGE_DIR,
    prepare,
    DEFAULT_STATEFILE,
    submit,
    SBOMB_KEY,
    SECSCAN_KEY,
)
from tests.helpers import mock_dev_env


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
        "clients": {
            "sbom": {
                "department": "charming_engineering",
                "email": "luca.bello@canonical.com",
                "sbom-service-url": "https://sbom-request-test.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
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
        "clients": {
            "sbom": {
                "department": "charming_engineering",
                "email": "luca.bello@canonical.com",
                "sbom-service-url": "https://sbom-request-test.canonical.com",
                "team": "observability",
            },
            "secscan": {},
        },
    }
