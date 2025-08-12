"""Main sbomber tool."""

import logging
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from subprocess import CalledProcessError
from tempfile import TemporaryDirectory
from typing import Dict

import apt
from craft_archives.repo import apt_ppa
from craft_archives.repo.apt_key_manager import AptKeyManager
from craft_archives.repo.apt_sources_manager import AptSourcesManager
from craft_archives.repo.package_repository import PackageRepository

from clients.client import Client, DownloadError, UploadError
from clients.sbom import SBOMber
from clients.secscanner import Scanner, ScannerType
from state import (
    RETRYABLE_STATUSES,
    Artifact,
    ArtifactType,
    Manifest,
    ProcessingStatus,
    ProcessingStep,
    SBOMClient,
    SecScanClient,
    Statefile,
    Token,
)

logger = logging.getLogger("sbomber")

DEFAULT_STATEFILE = Path(".statefile.yaml")
DEFAULT_MANIFEST = Path("manifest.yaml")
DEFAULT_REPORTS_DIR = Path("reports")
DEFAULT_PACKAGE_DIR = Path("pkgs")

SBOMB_KEY = "sbom"
SECSCAN_KEY = "secscan"


class InvalidStateTransitionError(Exception):
    """Raised if you run sbomber commands in an inconsistent order."""


def _download_cmd(bin: str, artifact: Artifact):
    channel_arg = f" --channel {channel}" if (channel := artifact.channel) else ""
    revision_arg = f" --revision {revision}" if (revision := artifact.version) else ""
    base_arg = f" --base {base}" if bin == "juju" and (base := artifact.base) else ""
    progress_arg = " --no-progress" if bin == "juju" else ""
    return shlex.split(
        f"{bin} download {artifact.name}{progress_arg}{channel_arg}{revision_arg}{base_arg}"
    )


def _download_rock(artifact: Artifact) -> str:
    """Download a rock from the rock store."""
    cmd = shlex.split(
        f"skopeo copy docker://{artifact.image}:{artifact.version} oci:{artifact.name}:{artifact.version}"
    )
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if "FATA" in proc.stderr:
        # wrong output starts with `FATA`
        logger.error(f"Could not fetch the OCI image. Error output: {proc.stderr}")
        raise DownloadError("OCI image download failure")

    # skopeo will create a directory with the unpacked OCI image. we still need to tar it.
    tar_cmd = shlex.split(
        f"tar -cvzf {artifact.name}_{artifact.version}.rock -C {artifact.name} ."
    )
    try:
        proc = subprocess.run(tar_cmd, capture_output=True, text=True, check=True)
    except CalledProcessError:
        raise DownloadError(f"failed to tar the downloaded OCI image with {' '.join(tar_cmd)!r}")
    finally:
        # we still have a directory we'd probably like to clean up.
        shutil.rmtree(f"./{artifact.name}")

    return f"{artifact.name}_{artifact.version}.rock"


def _download_charm(artifact: Artifact) -> str:
    """Download a charm from the charm store."""
    cmd = _download_cmd("juju", artifact)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # example output is:
    # Fetching charm "parca-k8s" revision 299
    # Install the "parca-k8s" charm with:
    #     juju deploy ./parca-k8s_r299.charm

    # fetch "parca-k8s_r299.charm"

    if "permission denied" in proc.stderr:
        logger.error(
            f"error fetching charm from juju; "
            f"ensure that the juju snap can write to the CWD {Path()}"
        )
        raise DownloadError("permission denied")

    # for whatever flipping reason this goes to stderr even if the download succeeded
    return proc.stderr.strip().splitlines()[-1].split()[-1][2:]


def _download_snap(artifact: Artifact) -> str:
    """Download a snap from the snap store."""
    cmd = _download_cmd("snap", artifact)
    proc = subprocess.run(cmd, capture_output=True, text=True)

    # example output is:
    # Fetching snap "jhack"
    # Fetching assertions for "jhack"
    # Install the snap with:
    #    snap ack jhack_445.assert
    #    snap install jhack_445.snap

    # fetch "jhack_445.snap"
    return proc.stdout.splitlines()[-1].split()[-1]


def _download_deb(artifact: Artifact) -> str:
    """Download a deb from the ubuntu archive."""
    repo_base = {
        "type": "apt",
        #                "architectures": [artifact.arch],  # TODO: see below
        "series": artifact.base,
        "pocket": artifact.pocket or "updates",
        "components": ["main", "universe"],
        "key-id": "F6ECB3762474EDA9D21B7022871920D1991BC93C",  # The Ubuntu archive key
    }

    repos = []

    if artifact.arch in ["i386", "amd64"]:
        repos.append(
            PackageRepository.unmarshal(
                {
                    **repo_base,
                    "url": "http://archive.ubuntu.com/ubuntu/",
                }
            )
        )
    else:
        repos.append(
            PackageRepository.unmarshal(
                {
                    **repo_base,
                    "url": "http://ports.ubuntu.com/ubuntu-ports/",
                }
            )
        )

    if artifact.ppa is not None:
        repos.append(
            PackageRepository.unmarshal(
                {
                    **repo_base,
                    "url": f"https://ppa.launchpadcontent.net/{artifact.ppa}/ubuntu/",
                    "key-id": apt_ppa.get_launchpad_ppa_key_id(ppa=artifact.ppa),
                    "pocket": "release",
                    "components": ["main"],
                }
            )
        )

    with TemporaryDirectory() as tmpdir:
        apt_root = Path(tmpdir)
        apt_dir = apt_root / "etc/apt"
        sources_d = apt_dir / "sources.list.d"
        sources_d.mkdir(parents=True, exist_ok=True)

        trusted_d = apt_dir / "trusted.gpg.d"
        trusted_d.mkdir(parents=True, exist_ok=True)

        asm = AptSourcesManager(sources_list_d=sources_d, keyrings_dir=trusted_d)
        akm = AptKeyManager(keyrings_path=trusted_d, key_assets=trusted_d)
        for repo in repos:
            akm.install_package_repository_key(package_repo=repo)
            asm.install_package_repository_sources(package_repo=repo)

        # TODO: this could be done by AptSourcesManager,
        # But it tries `dpkg --add-architecture` instead
        conf_d = apt_dir / "apt.conf.d"
        conf_d.mkdir(parents=True, exist_ok=True)
        with open(conf_d / "00arch", "w") as f:
            f.write(f'APT::Architecture "{artifact.arch}";\n')
        for source in sources_d.glob("*.sources"):
            with open(source, "r+") as f:
                lines = f.readlines()
                f.seek(0)
                for line in lines:
                    if line.startswith("Architectures:"):
                        f.write(f"Architectures: {artifact.arch}\n")
                    else:
                        f.write(line)
                f.truncate()

        # apt-get update
        subprocess.run(shlex.split(""))
        cache = apt.Cache(rootdir=str(apt_root))
        assert cache.update(), "Failed to update apt cache"

        cache.open()
        # ?
        package = cache[artifact.package].candidate
        assert package is not None, "Failed to find package"

        # apt-get source <pkg-name>
        obj_name = Path(package.fetch_binary()).name
        cache.close()

        return obj_name


def _download_from_pypi(artifact: Artifact) -> str:
    """Download a package from PyPI."""
    uvx = shutil.which("uvx")
    if uvx:
        cmd = ["uvx", "pip", "download", "--no-deps"]
    else:
        cmd = ["python3", "-m", "pip", "download", "--no-deps"]
    if artifact.type is ArtifactType.wheel:
        cmd.append("--only-binary=:all:")
    elif artifact.type is ArtifactType.sdist:
        cmd.append("--no-binary=:all:")
    cmd.append(artifact.name)
    if artifact.version:
        cmd[-1] += f"=={artifact.version}"

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except CalledProcessError as e:
        logger.error("Failed to download %s from PyPI: %r", artifact.name, e.stderr)
        raise DownloadError(f"Failed to download {artifact.name} from PyPI") from e

    # The output will contain a line starting with "Saved " # followed by the filename. For example:
    # $ python3 -m pip download --no-deps ops-scenario
    # Collecting ops-scenario
    # [...]
    # Saved ./ops_scenario-7.22.0-py3-none-any.whl      #  <<< this is what we're after
    # Successfully downloaded ops-scenario
    #
    # If the file was already downloaded, it will say:
    # $ python3 -m pip download --no-deps ops
    # Collecting ops
    #   File was already downloaded ./ops-2.22.0-py3-none-any.whl
    # Successfully downloaded ops
    for line in proc.stdout.splitlines():
        if line.startswith("Saved "):
            filename = line.split("Saved ", 1)[-1].strip()
            if filename:
                return filename
        elif line.startswith("  File was already downloaded"):
            # If the user wants a fresh copy, they need to remove the existing one manually.
            logger.info("File already downloaded")
            return line.rsplit(None, 1)[-1].strip()
    raise DownloadError(f"Failed to find the file name for {artifact.name}: {proc.stdout!r}")


def _download_artifact(artifact: Artifact):
    atype = artifact.type

    print(f"fetching {atype.value} {artifact.name}")

    if atype is ArtifactType.rock:
        obj_name = _download_rock(artifact)

    elif atype is ArtifactType.charm:
        obj_name = _download_charm(artifact)

    elif atype is ArtifactType.snap:
        obj_name = _download_snap(artifact)

    elif atype is ArtifactType.deb:
        obj_name = _download_deb(artifact)

    elif atype is ArtifactType.sdist or atype is ArtifactType.wheel:
        obj_name = _download_from_pypi(artifact)

    else:
        raise ValueError(f"unsupported atype {atype}")

    return obj_name


def prepare(
    manifest: Path = DEFAULT_MANIFEST,
    statefile: Path = DEFAULT_STATEFILE,
    pkg_dir: Path = DEFAULT_PACKAGE_DIR,
):
    """Prepare the stage.

    Copies all artifacts in a central location, and creates a statefile.
    """
    if statefile.exists():
        logger.debug(f"found statefile: resuming from {statefile}")
        meta = Statefile.load(statefile)
    else:
        logger.debug(f"fresh run: loading manifest {manifest}")
        meta = Manifest.load(manifest)

    cd = os.getcwd()
    logger.info(f"preparing from project root: {cd}")

    # in case juju doesn't let us download straight to the pkg dir,
    # we could download all to ./ and later copy (mv?) to pkg_dir?
    pkg_dir.mkdir(exist_ok=True)
    os.chdir(pkg_dir)

    artifact_names = set()
    done = []

    for artifact in meta.artifacts:
        if artifact.processing.started:
            logger.error(
                f"Already started processing on {artifact.name}: no point in preparing again."
            )
            continue

        name = artifact.name

        if name in artifact_names:
            logger.error(f"Artifact name {name} is not unique: skipping...")
            continue

        artifact_names.add(name)

        status = ProcessingStatus.success
        obj_name = None

        if source := artifact.source:
            print(f"fetching local source {name}")
            source_path = Path(source).expanduser().resolve()
            if not source_path.exists() or not source_path.is_file():
                logger.error(f"invalid source path: {source_path!r}")
                status = ProcessingStatus.error
            else:
                # copy over to the package dir
                # FIXME: risk of filename conflict.
                (Path() / source_path.name).write_bytes(source_path.read_bytes())
                obj_name = str(source_path)
        else:
            print(f"downloading source {name}")
            try:
                # TODO: could guess the revision/version number from the downloaded filename:
                #   e.g. `mycharm-k8s_r42.charm` or `jhack_443.snap`
                obj_name = _download_artifact(artifact)
            except (ValueError, CalledProcessError, DownloadError):
                logger.exception(f"failed downloading {artifact.name}")
                status = ProcessingStatus.error

        artifact.object = obj_name
        done.append((name, status))

        for client_status in artifact.processing_statuses:
            client_status.step = ProcessingStep.prepare
            client_status.status = status

    if not done:
        raise InvalidStateTransitionError("nothing to prepare")

    logger.debug("cleaning up snap .assert files")
    for path in Path().glob("*.assert"):
        path.unlink()

    os.chdir(cd)

    meta.dump(statefile)
    print(f"all artifacts gathered in {pkg_dir.absolute()}:")
    for file, status in done:
        print(f"\t{file[:50]:<50} {status.value.upper():>10}")


def _get_sbomber(client_meta: SBOMClient) -> SBOMber:
    return SBOMber(
        email=client_meta.email,
        department=client_meta.department,
        team=client_meta.team,
        service_url=client_meta.service_url,
    )


def _get_scanner(client_meta: SecScanClient) -> Scanner:  # type:ignore
    return Scanner(
        scanner=ScannerType[client_meta.scanner],
    )


def _get_clients(meta: Manifest) -> Dict[str, Client]:
    clients_meta = meta.clients

    if not clients_meta:
        exit("Invalid `manifest.clients` definition: no clients defined.")

    out = {}
    for client, client_meta in clients_meta:
        if not client_meta:
            logger.debug(f"skipping client {client}: not in metadata")
            continue

        if client == SBOMB_KEY:
            out[client] = _get_sbomber(client_meta)  # type:ignore
        elif client == SECSCAN_KEY:
            out[client] = _get_scanner(client_meta)  # type:ignore
        else:
            exit(f"Invalid `manifest.clients.{client}` definition: unknown client type.")

    return out


def submit(statefile: Path = DEFAULT_STATEFILE, pkg_dir: Path = DEFAULT_PACKAGE_DIR):
    """Submit all artifacts to the various backends."""
    try:
        meta = Statefile.load(statefile)
    except FileNotFoundError:
        raise InvalidStateTransitionError(
            f"statefile not found at {statefile}: forgetting to `prepare`?"
        )

    if not pkg_dir.exists():
        exit("no pkg_dir dir found: run `prepare` first.")

    clients = _get_clients(meta)
    done = []

    # TODO: parallelize between all artifacts
    for artifact in meta.artifacts:
        name = artifact.name
        obj = artifact.object
        if not obj:
            logger.warning(
                f"skipping {name}: no `object` path yet "
                f"(probably 'prepare' failed for this artifact)"
            )
            continue

        obj_path = pkg_dir / obj
        if not obj_path.exists() or not obj_path.is_file():
            # we exit because this is an inconsistent state; we did 'prepare',
            # but the 'object' field doesn't point to a valid file.
            raise InvalidStateTransitionError(
                f"invalid `object` field for artifact {name!r}: {obj_path}."
            )

        for client_name, client in clients.items():
            if artifact.clients and client_name not in artifact.clients:
                logger.debug(f"skipping {artifact.name}: {client_name}")
                continue

            client = clients.get(client_name)
            if not client:
                raise ValueError(f"invalid client_name: {client_name} unsupported")

            # it only makes sense to submit if the artifact is in prepare:success or submit:{retryable}
            status = artifact.processing.get_status(client_name)
            if not artifact.processing.check_step(
                client_name,
                *(
                    (ProcessingStep.prepare, ProcessingStatus.success),
                    *((ProcessingStep.submit, ps) for ps in RETRYABLE_STATUSES),
                ),
            ):
                logger.debug(f"Skipping step: {name} cannot be processed in status: {status}.")
                continue

            done.append(f"({client_name}):{artifact.name}")

            logger.info(f"submitting to {client_name}...")
            new_status = ProcessingStatus.pending

            try:
                token = client.submit(filename=obj_path, artifact=artifact)
            except (Exception, UploadError):
                logger.exception(f"Failed to submit the artifact {artifact.name}")
                new_status = ProcessingStatus.error
                token = None

            if token:
                print(f"{client_name}: {artifact.name} submitted ({Token(token).cropped})")
            else:
                print(f"submission for {client_name}: {artifact.name} FAILED (see logs)")
            status.status = new_status
            status.step = ProcessingStep.submit
            status.token = token

    meta.dump(statefile)

    if not done:
        raise InvalidStateTransitionError("no artifacts can be submitted")

    print(f"submitted {done}")


def poll(statefile: Path = DEFAULT_STATEFILE, wait: bool = False, timeout: int = 15):
    """Update the report status for all submitted artifacts."""
    meta = Statefile.load(statefile)
    clients = _get_clients(meta)

    done = []
    error_found = False
    pending_found = False

    # TODO: parallelize between all artifacts
    for client_name, client in clients.items():
        print()
        print(f"\t{'artifact':<50}  \t{client_name.upper()} status")
        # block until all are completed
        for artifact in meta.artifacts:
            if artifact.clients and client_name not in artifact.clients:
                logger.debug(f"skipping {artifact.name}: {client_name}")
                continue

            token = artifact.processing.get_token(client_name)
            if not token:
                logger.error(
                    f"artifact {artifact.name} has no token: have you 'submitted' already?"
                )
                print(f"\t{artifact.name[:50]:<50}::\tno token")
                continue

            status = artifact.processing.get_status(client_name)

            if not artifact.processing.check_step(
                client_name,
                (ProcessingStep.submit, ProcessingStatus.pending),
            ):
                logger.debug(
                    f"skipping {artifact.name}: {status}. "
                    f"it only makes sense to poll pending processing requests."
                )
                print(f"\t{artifact.name[:50]:<50}::\t{status.status.value}")
                continue

            # this way we can report if it makes sense to call poll once again or not
            done.append(f"({client_name}):{artifact.name}")

            logger.debug(f"polling {token.cropped}...")
            if wait:
                try:
                    client.wait(token, status=ProcessingStatus.success, timeout=timeout)
                    # if wait ends without errors, it means we're good
                    new_status = ProcessingStatus.success
                except TimeoutError:
                    logger.error(f"timeout waiting for {token.cropped}")
                    new_status = ProcessingStatus.pending
                    pending_found = True
                except Exception:
                    # print the whole token here, people may need it to troubleshoot
                    logger.exception(f"unexpected error waiting for {token}")
                    new_status = ProcessingStatus.error
            else:
                new_status = client.query_status(token)

            status_before = status.status
            print(f"\t{artifact.name[:50]:<50}::\t{status_before.value} --> {new_status.value}")
            status.status = new_status

            if new_status in {ProcessingStatus.error, ProcessingStatus.failed}:
                error_found = True

    meta.dump(statefile)

    if not done:
        print(
            "all artifacts are either in the success or error state so nothing will change anymore in the state (and you knew that already)."
        )

    # return an exit code. if there were errors, exit code should be 1, some pending items = 42
    if error_found:
        return 1
    if pending_found:
        return 42
    return 0


def download(statefile: Path = DEFAULT_STATEFILE, reports_dir=DEFAULT_REPORTS_DIR):
    """Download all available reports."""
    meta = Statefile.load(statefile)
    clients = _get_clients(meta)

    reports_dir = reports_dir.expanduser().resolve()
    reports_dir.mkdir(exist_ok=True)

    done = []
    # TODO: parallelize between all artifacts
    for client_name, client in clients.items():
        print(f"collecting {client_name.upper()}s...")
        for artifact in meta.artifacts:
            if artifact.clients and client_name not in artifact.clients:
                logger.debug(f"skipping {artifact.name}: {client_name}")
                continue
            logger.debug(f"processing {artifact.name}")

            artifact_name = artifact.name
            status = artifact.processing.get_status(client_name)

            # if we didn't submit and succeeded (or don't know yet)...
            if not artifact.processing.check_step(
                client_name,
                (ProcessingStep.submit, ProcessingStatus.success),
                (ProcessingStep.submit, ProcessingStatus.pending),
            ):
                logger.debug(
                    f"skipping {artifact.name}: {status}. "
                    f"it only makes sense to poll pending processing requests."
                )
                continue

            # we already checked that the current state of this artifact is 'submit';
            # now we check it's reported as 'success'.
            if status.status != ProcessingStatus.success:
                # we are not sure that this WILL in fact fail, perhaps we simply didn't
                # run `poll` or in the meantime it's succeeded.
                logger.warning(
                    f"attempting to download non-completed artifact {artifact_name} may not work. "
                    "Consider `polling` first."
                )

            filename = (
                f"{artifact_name}.{client_name}{'.html' if client_name == 'secscan' else '.json'}"
            )

            done.append((f"({client_name}):{artifact.name}", filename))

            token = artifact.processing.get_token(client_name)
            if not token:
                logger.error(f"{artifact_name} does not have a token; skipping...")
                continue

            location = reports_dir / filename

            try:
                client.download_report(token, location)
                new_status = ProcessingStatus.success
                logger.debug(f"downloaded {client_name} for {artifact.name} to {location}")
            except DownloadError:
                logger.exception(f"error downloading {client_name} for {artifact.name}.")
                new_status = ProcessingStatus.error
                logger.debug(f"download failed ({client_name}) for {artifact.name}")

            status.status = new_status

    # download-artifact should not really mutate the statefile if not for the success status update
    meta.dump(statefile)

    if not done:
        raise InvalidStateTransitionError("no artifacts can be downloaded")

    print(f"all downloaded reports ready in {reports_dir!r}:")
    for artifact_name, report_file in done:
        print(f"\t{artifact_name}\n\t{report_file}\n")


if __name__ == "__main__":
    prepare()
