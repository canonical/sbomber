"""Main sbomber tool."""

import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Dict, List

import yaml

from clients.client import Client, ProcessingStatus
from clients.sbom import SBOMber
from clients.secscanner import Scanner

logger = logging.getLogger("sbomber")

DEFAULT_STATEFILE = Path(".statefile.yaml")
DEFAULT_MANIFEST = Path("manifest.yaml")
DEFAULT_REPORTS_DIR = Path("reports")
DEFAULT_PACKAGE_DIR = Path("pgks")

SBOMB_KEY = "sbom"
SECSCAN_KEY = "secscan"


def _download_cmd(bin: str, artifact):
    channel_arg = f" --channel {channel}" if (channel := artifact.get("channel")) else ""
    revision_arg = f" --revision {revision}" if (revision := artifact.get("revision")) else ""
    progress_arg = " --no-progress" if bin == "juju" else ""
    return shlex.split(
        f"{bin} download {artifact['name']}{progress_arg}{channel_arg}{revision_arg}"
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


def prepare(
    manifest: Path = DEFAULT_MANIFEST,
    statefile: Path = DEFAULT_STATEFILE,
    pkg_dir: Path = DEFAULT_PACKAGE_DIR,
):
    """Prepare the stage.

    Copies all artifacts in a central location, and clientss a statefile.
    """
    meta = yaml.safe_load(manifest.read_text())

    cd = os.getcwd()
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
    statefile.write_text(yaml.safe_dump(meta))

    print(f"all ready in {pkg_dir.absolute()}.")


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


def _update_statefile(statefile: Path, contents: dict):
    logger.debug("updating statefile")
    statefile.write_text(yaml.safe_dump(contents))


def submit(statefile: Path = DEFAULT_STATEFILE, pkg_dir: Path = DEFAULT_PACKAGE_DIR):
    """Submit all artifacts to the various backends."""
    meta = yaml.safe_load(statefile.read_text())

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

    _update_statefile(statefile, meta)
    print("submitted all artifacts")


def poll(statefile: Path = DEFAULT_STATEFILE, wait: bool = False, timeout: int = 15):
    """Update the report status for all submitted artifacts."""
    meta = yaml.safe_load(statefile.read_text())
    clients = _get_clients(meta)

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
                logger.info(f"polling {artifact_id}...")
                if wait:
                    try:
                        client.wait(artifact_id, status=ProcessingStatus.success, timeout=timeout)
                        # if wait ends without errors, it means we're good
                        status = ProcessingStatus.success
                    except TimeoutError:
                        logger.error(f"timeout waiting for {artifact_id}")
                        status = ProcessingStatus.pending
                else:
                    status = client.query_status(artifact_id)

                print(f"\t{artifact_id}\t{status.value}")
                requests[artifact_id] = status

    _update_statefile(statefile, meta)


def download(statefile: Path = DEFAULT_STATEFILE, reports_dir=DEFAULT_REPORTS_DIR):
    """Download all available reports."""
    meta = yaml.safe_load(statefile.read_text())
    clients = _get_clients(meta)

    # TODO: parallelize between all artifacts
    for client_name, client in clients.items():
        print(f"collecting {client_name}s...")
        for artifact in _get_artifacts(meta):
            requests = artifact.get(client_name, {})
            if not requests:
                logger.error(f"artifact {artifact['name']} has no requests.")
                continue

            for artifact_id, status in requests.items():
                if status != "Completed":
                    logger.error(
                        "attempting to download a non-completed artifact may not work. "
                        "Consider `polling` first."
                    )

                location = reports_dir / (artifact_id + ".sbom")
                try:
                    client.download_report(artifact_id, location)
                except Exception:
                    logger.error(f"error downloading {client_name} for {artifact_id}.")
                    requests[artifact_id] = "Error"
                    continue

                print(f"downloaded {client_name} for {artifact_id} to {location}")

    _update_statefile(statefile, meta)
    print(f"all downloaded reports ready in {reports_dir}")


if __name__ == "__main__":
    prepare()
