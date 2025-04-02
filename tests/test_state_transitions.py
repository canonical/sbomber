from contextlib import nullcontext

import pytest

from sbomber import prepare, InvalidStateTransition, submit, poll, download
from tests.helpers import mock_dev_env


@pytest.mark.parametrize(
    "state_transitions, expect_ctx",
    (
        # happy paths
        ((prepare,), nullcontext()),
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
        ((submit,), pytest.raises(InvalidStateTransition)),
        ((prepare, prepare), pytest.raises(InvalidStateTransition)),
        ((prepare, submit, prepare), pytest.raises(InvalidStateTransition)),
        ((prepare, submit, submit), pytest.raises(InvalidStateTransition)),
        ((prepare, submit, poll, prepare), pytest.raises(InvalidStateTransition)),
        ((prepare, submit, poll, submit), pytest.raises(InvalidStateTransition)),
        ((prepare, submit, download, prepare), pytest.raises(InvalidStateTransition)),
        ((prepare, submit, download, submit), pytest.raises(InvalidStateTransition)),
    ))
def test_state_transitions(project, state_transitions, expect_ctx):
    mock_dev_env(project)
    with expect_ctx:
        for transition in state_transitions:
            transition()
