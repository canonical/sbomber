from contextlib import nullcontext

import pytest

from sbomber import (
    DEFAULT_STATEFILE,
    InvalidStateTransitionError,
    download,
    poll,
    prepare,
    submit,
)
from state import ProcessingStatus, ProcessingStep, Statefile
from tests.conftest import mock_package_download
from tests.helpers import mock_dev_env

raises_ISTE = pytest.raises(InvalidStateTransitionError)  # noqa: N816


@pytest.mark.parametrize(
    "initial_status, expected_status, ctx",
    (
        # not started goes to pending
        (
            {"step": "prepare", "status": ProcessingStatus.success.value},
            {"step": "prepare", "status": ProcessingStatus.success.value},
            nullcontext(),
        ),
        # all other are no-ops
        (
            {
                "step": ProcessingStep.submit.value,
                "status": ProcessingStatus.pending.value,
                "token": "secscan-token",
            },
            {
                "step": ProcessingStep.submit.value,
                "status": ProcessingStatus.pending.value,
                "token": "secscan-token",
            },
            raises_ISTE,
        ),
        (
            {
                "step": ProcessingStep.submit.value,
                "status": ProcessingStatus.error.value,
                "token": "secscan-token",
            },
            {
                "step": ProcessingStep.submit.value,
                "status": ProcessingStatus.error.value,
                "token": "secscan-token",
            },
            raises_ISTE,
        ),
        (
            {
                "step": ProcessingStep.submit.value,
                "status": ProcessingStatus.failed.value,
                "token": "secscan-token",
            },
            {
                "step": ProcessingStep.submit.value,
                "status": ProcessingStatus.failed.value,
                "token": "secscan-token",
            },
            raises_ISTE,
        ),
        (
            {
                "step": ProcessingStep.submit.value,
                "status": ProcessingStatus.success.value,
                "token": "secscan-token",
            },
            {
                "step": ProcessingStep.submit.value,
                "status": ProcessingStatus.success.value,
                "token": "secscan-token",
            },
            raises_ISTE,
        ),
    ),
)
def test_status_change_prepare(project, tmp_path, initial_status, expected_status, ctx):
    (tmp_path / "foo.charm").write_text("ceci est une charm")

    mock_dev_env(
        project,
        step=ProcessingStep.prepare,
        status=ProcessingStatus.success,
        statefile={
            "artifacts": [
                {
                    "name": "foo",
                    "object": str(tmp_path / "foo.charm"),
                    "processing": {"secscan": initial_status},
                    "source": str(tmp_path / "foo.charm"),
                    "type": "charm",
                },
            ],
            "clients": {"secscan": {}},
        },
    )
    with ctx:
        prepare()

    state = Statefile.load(project / DEFAULT_STATEFILE)
    artifact = state.artifacts[0].processing.get_status("secscan")
    assert artifact.model_dump(mode="json", exclude_none=True) == expected_status


@pytest.mark.parametrize(
    "state_transitions, expect_ctx",
    (
        # happy paths
        ((prepare,), nullcontext()),
        ((prepare, prepare), nullcontext()),
        ((prepare, prepare, prepare), nullcontext()),
        ((prepare, submit), nullcontext()),
        ((prepare, submit, poll), nullcontext()),
        ((prepare, submit, poll, download), nullcontext()),
        ((prepare, submit, poll, download, poll), nullcontext()),
        ((prepare, submit, poll, download, poll, download), nullcontext()),
        ((prepare, submit, poll, download, poll, poll), nullcontext()),
        ((prepare, submit, poll, poll, poll), nullcontext()),
        ((prepare, submit, download, poll, poll), nullcontext()),
        ((prepare, submit, download, poll, download, poll), nullcontext()),
        # sad paths
        ((submit,), raises_ISTE),
        ((prepare, submit, prepare), raises_ISTE),
        ((prepare, submit, submit), raises_ISTE),
        ((prepare, submit, poll, prepare), raises_ISTE),
        ((prepare, submit, poll, submit), raises_ISTE),
        ((prepare, submit, download, prepare), raises_ISTE),
        ((prepare, submit, download, submit), raises_ISTE),
    ),
)
def test_state_transitions(project, state_transitions, expect_ctx):
    mock_dev_env(project)
    with mock_package_download(project, "foo.charm"):
        with expect_ctx:
            for transition in state_transitions:
                transition()
