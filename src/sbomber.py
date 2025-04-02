"""Main sbomber tool."""

import logging
import os
import shlex
import subprocess
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import yaml

from clients.client import Client, ProcessingStatus
from clients.sbom import SBOMber
from clients.secscanner import Scanner

logger = logging.getLogger("sbomber")

DEFAULT_STATEFILE = Path(".statefile.yaml")
DEFAULT_MANIFEST = Path("manifest.yaml")
DEFAULT_REPORTS_DIR = Path("reports")
DEFAULT_PACKAGE_DIR = Path("pkgs")

SBOMB_KEY = "sbom"
SECSCAN_KEY = "secscan"


class InvalidStateTransitionError(Exception):
    """Raised if you run sbomber commands in an inconsistent order."""


# key under which the current state is stored in the statefile
STATE_METADATA_KEY = "sbombing-state"


class _SbombingState(Enum):
    """Valid states for the sbomber tool.

    The user must prepare and submit.
    After that, they may poll and/or download any number of
    times, in whatever order they like, but they shouldn't probably submit/prepare again.
    - Preparing again should be harmless but pointless.
    - Submitting again might only have sense if there was a transient client error,
      but usually those don't go away by themselves.
    """

    # actual states.
    prepared = "prepared"
    submitted = "submitted"

    @staticmethod
    def check_state(statefile: dict, *, expect: Sequence["_SbombingState"]):
        """Verify that this state is a valid next state given this statefile's current state.

        Will raise an InvalidStateTransitionError if not.
        """
        current = set(statefile.get(STATE_METADATA_KEY, ()))
        if not current:
            # no current state = we didn't do anything yet.
            return

        expected = {e.value for e in expect}
        if current.symmetric_difference(expected):
            raise InvalidStateTransitionError(
                f"Cannot run this action; expecting {expected}: got {current}."
            )


def _download_cmd(bin: str, artifact):
    channel_arg = f" --channel {channel}" if (channel := artifact.get("channel")) else ""
    revision_arg = f" --revision {revision}" if (revision := artifact.get("revision")) else ""
    base_arg = f" --base {base}" if bin == "juju" and (base := artifact.get("base")) else ""
    progress_arg = " --no-progress" if bin == "juju" else ""
    return shlex.split(
        f"{bin} download {artifact['name']}{progress_arg}{channel_arg}{revision_arg}{base_arg}"
    )


def _download_artifact(artifact: dict, atype: str):
    if atype == "rock":
        exit(
            "we don't support yet downloading OCI images; "
            "for now you need to specify `source` for rock types."
        )

    elif atype == "charm":
        print(f"fetching charm {artifact}")
        cmd = _download_cmd("juju", artifact)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        # example output is:
        # Fetching charm "parca-k8s" revision 299
        # Install the "parca-k8s" charm with:
        #     juju deploy ./parca-k8s_r299.charm

        # fetch "parca-k8s_r299.charm"

        if proc.returncode != 0:
            logger.error(f"command {' '.join(cmd)} errored out.")

        # for whatever fucking reason this goes to stderr even if the download succeeded
        obj_name = proc.stderr.splitlines()[-1].split()[-1][2:]

    elif atype == "snap":
        print(f"fetching snap {artifact}")

        proc = subprocess.run(_download_cmd("snap", artifact), capture_output=True, text=True)

        # example output is:
        # Fetching snap "jhack"
        # Fetching assertions for "jhack"
        # Install the snap with:
        #    snap ack jhack_445.assert
        #    snap install jhack_445.snap

        # fetch "jhack_445.snap"
        obj_name = proc.stdout.splitlines()[-1].split()[-1]

    else:
        raise ValueError(f"unsupported atype {atype}")

    return obj_name


def _load_statefile(statefile: Path, *, expect: Sequence[_SbombingState]):
    if not statefile.exists():
        raise InvalidStateTransitionError("project not initialized: run `prepare` first.")
    meta = yaml.safe_load(statefile.read_text())
    _SbombingState.check_state(meta, expect=expect)
    return meta


def _update_statefile(statefile: Path, contents: dict, state: Optional[_SbombingState] = None):
    if state:
        state_val = state.value
        logger.debug(f"updating statefile with state: {state_val}")
        current_states = set(contents.get(STATE_METADATA_KEY, ()))
        current_states.add(state.value)
        contents[STATE_METADATA_KEY] = sorted(current_states)
    else:
        logger.debug("updating statefile")
    statefile.write_text(yaml.safe_dump(contents))


def prepare(
    manifest: Path = DEFAULT_MANIFEST,
    statefile: Path = DEFAULT_STATEFILE,
    pkg_dir: Path = DEFAULT_PACKAGE_DIR,
):
    """Prepare the stage.

    Copies all artifacts in a central location, and clientss a statefile.
    """
    meta = yaml.safe_load(manifest.read_text())

    if statefile.exists():
        raise InvalidStateTransitionError(
            f"existing statefile found at {statefile}. "
            f"Running `prepare` here will overwrite it. "
            f"Delete it manually if you're sure."
        )

    cd = os.getcwd()
    logger.info(f"preparing from project root: {cd}")

    # in case juju doesn't let us download straight to the pkg dir,
    # we could download all to ./ and later copy (mv?) to pkg_dir?
    pkg_dir.mkdir(exist_ok=True)
    os.chdir(pkg_dir)

    for artifact in _get_artifacts(meta):
        try:
            name = artifact["name"]
            source = artifact.get("source")
            atype = artifact["type"]

            if source:
                print(f"fetching local source {name}")
                source_path = Path(source)
                if not source_path.exists() or not source_path.is_file():
                    exit(f"invalid source path: {source!r}")

                # copy over to the package dir
                # FIXME: risk of filename conflict.
                (Path() / source_path.name).write_bytes(source_path.read_bytes())
                obj_name = str(source_path.resolve())
            else:
                obj_name = _download_artifact(artifact, atype)

        except TypeError:
            exit(f"Invalid artifact spec: {artifact}")

        artifact["object"] = obj_name

    logger.debug("cleaning up snap .assert files")
    for path in Path().glob("*.assert"):
        path.unlink()

    os.chdir(cd)

    logger.info(f"creating statefile: {statefile}")
    _update_statefile(statefile, meta, state=_SbombingState.prepared)
    print(f"all artifacts gathered in {pkg_dir.absolute()}.")


def _get_sbomber(client_meta) -> SBOMber:
    try:
        email = client_meta["email"]
        department = client_meta["department"]
        team = client_meta["team"]
    except KeyError:
        exit("invalid clients.sbom definition: must contain all of `email, department, team`.")

    return SBOMber(
        email=email,
        department=department,
        team=team,
        service_url=client_meta.get("sbom-service-url"),
    )


def _get_scanner(client_meta) -> Scanner:
    return Scanner()


def _get_artifacts(meta) -> List[dict]:
    artifacts_meta = meta.get("artifacts", [])
    if not artifacts_meta:
        exit("invalid `manifest.artifacts`: no artifacts defined.")
    return artifacts_meta


def _get_clients(meta) -> Dict[str, Client]:
    clients_meta = meta.get("clients", {})

    if not clients_meta:
        exit("Invalid `manifest.clients` definition: no clients defined.")

    out = {}
    for client, client_meta in clients_meta.items():
        if client == SBOMB_KEY:
            out[client] = _get_sbomber(client_meta)
        elif client == SECSCAN_KEY:
            out[client] = _get_scanner(clients_meta)
        else:
            exit(f"Invalid `manifest.clients.{client}` definition: unknown client type.")

    return out


def submit(statefile: Path = DEFAULT_STATEFILE, pkg_dir: Path = DEFAULT_PACKAGE_DIR):
    """Submit all artifacts to the various backends."""
    meta = _load_statefile(statefile, expect=(_SbombingState.prepared,))

    if not pkg_dir.exists():
        exit("no pkg_dir dir found: run `prepare` first.")

    clients = _get_clients(meta)

    # TODO: parallelize between all artifacts
    for artifact in _get_artifacts(meta):
        name = artifact["name"]
        obj = artifact.get("object", "")

        # if artifact specifies its own "clients", use those instead.
        artifact_clients = artifact.get("clients", list(clients))
        if not artifact_clients:
            logger.warning(
                f"Cannot submit {name}: no report generators defined "
                f"please check your `clients` configs."
            )
            continue

        obj_path = pkg_dir / obj
        if not obj or not obj_path.exists() or not obj_path.is_file():
            exit(f"invalid `object` field for artifact {name!r}. Have you run `prepare`?")

        for key in artifact_clients:
            if key in {SECSCAN_KEY, SBOMB_KEY}:
                logger.info(f"requesting {key}...")
                token = clients[key].submit(
                    filename=obj_path, atype=artifact["type"], version=artifact.get("version")
                )
                print(f"{name}: {key} requested ({token})")

                statuses = artifact.get(key, {})
                statuses[token] = ProcessingStatus.pending.value
                artifact[key] = statuses

            else:
                raise ValueError(f"invalid client request key: {key} unsupported")

    _update_statefile(statefile, meta, state=_SbombingState.submitted)
    print("submitted all artifacts")


def poll(statefile: Path = DEFAULT_STATEFILE, wait: bool = False, timeout: int = 15):
    """Update the report status for all submitted artifacts."""
    meta = _load_statefile(statefile, expect=(_SbombingState.prepared, _SbombingState.submitted))
    clients = _get_clients(meta)

    error_found = False
    pending_found = False
    # TODO: parallelize between all artifacts
    for client_name, client in clients.items():
        print(f"artifact :: {client_name.upper()} status")
        # block until all are completed
        for artifact in _get_artifacts(meta):
            requests = artifact.get(client_name, {})
            if not requests:
                logger.error(f"artifact {artifact['name']} has no requests.")
                continue

            for artifact_id in requests:
                logger.debug(f"polling {artifact_id[:20]}[...]...")
                if wait:
                    try:
                        client.wait(artifact_id, status=ProcessingStatus.success, timeout=timeout)
                        # if wait ends without errors, it means we're good
                        status = ProcessingStatus.success
                    except TimeoutError:
                        logger.error(f"timeout waiting for {artifact_id[:20]}[...]")
                        status = ProcessingStatus.pending
                        pending_found = True
                else:
                    status = client.query_status(artifact_id)

                print(f"\t{artifact_id[:20]}[...]\t{status.value}")
                requests[artifact_id] = status.value
                if status == ProcessingStatus.error or status == ProcessingStatus.failed:
                    error_found = True

    _update_statefile(statefile, meta)
    # return an exit code. if there were errors, exit code should be 1, some pending items = 42
    if error_found:
        return 1
    if pending_found:
        return 42
    return 0


def download(statefile: Path = DEFAULT_STATEFILE, reports_dir=DEFAULT_REPORTS_DIR):
    """Download all available reports."""
    meta = _load_statefile(statefile, expect=(_SbombingState.prepared, _SbombingState.submitted))
    clients = _get_clients(meta)

    reports_dir.mkdir(exist_ok=True)

    # TODO: parallelize between all artifacts
    for client_name, client in clients.items():
        print(f"collecting {client_name}s...")
        for artifact in _get_artifacts(meta):
            artifact_name = artifact["name"]

            if client_name not in artifact:
                logger.error(f"artifact {artifact_name} has no requests.")
                continue

            for artifact_id, status in artifact.get(client_name, {}).items():
                if status != ProcessingStatus.success:
                    # we are not sure that this WILL in fact fail, perhaps we simply didn't
                    # run `poll` or in the meantime it's succeeded.
                    logger.warning(
                        "attempting to download a non-completed artifact may not work. "
                        "Consider `polling` first."
                    )

                filename = f"{artifact_name}.{client_name}{'.html' if client_name == 'secscan' else '.txt'}"

                location = reports_dir / filename
                try:
                    client.download_report(artifact_id, location)
                except Exception:
                    logger.exception(
                        f"error downloading {client_name} for {artifact_id[:20]}[...]."
                    )
                    continue

                print(f"downloaded {client_name} for {artifact_id[:20]}[...] to {location}")

    # download-artifact should not mutate the statefile
    # _update_statefile(statefile, meta)
    print(f"all downloaded reports ready in {reports_dir}")


if __name__ == "__main__":
    prepare()
