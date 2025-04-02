#!/usr/bin/env python3
"""Sbomber CLI."""

import os
from pathlib import Path

import typer

import sbomber
from clients.client import ArtifactType
from clients.sbom import SBOMber
from clients.secscanner import Scanner


def main():
    """Sbomber CLI."""
    import logging

    logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO").upper())

    def sbom(
        email: str = typer.Argument(..., help="The email to notify when the build is ready."),
        department: str = typer.Argument(..., help="The department this build belongs to."),
        team: str = typer.Argument(..., help="The team this build belongs to."),
        service_url: str = typer.Argument(None, help="The service URL to send API requests to."),
        artifact: Path = typer.Argument(
            ...,
            help="The artifact whose SBOM you want to generate. "
            f"Currently supported: ({list(ArtifactType)}).",
        ),
        version: str = typer.Argument("0", help="Artifact version to associate with the build."),
        output_file: Path = typer.Option(
            None, help="If left blank, output will be printed to stdout instead."
        ),
    ):
        """Submit a SBOM request for a single artifact and wait for the result."""
        sbomber = SBOMber(email=email, department=department, team=team, service_url=service_url)
        sbomber.run(
            artifact,
            atype=ArtifactType.from_path(artifact),
            version=version,
            output_file=output_file,
        )

    def secscan(
        artifact: Path = typer.Argument(
            ...,
            help="The artifact whose SBOM you want to generate. "
            f"Currently supported: ({list(ArtifactType)}).",
        ),
        output_file: Path = typer.Option(
            None, help="If left blank, output will be printed to stdout instead."
        ),
    ):
        """Submit a SECSCAN request for a single artifact and wait for the result."""
        Scanner().run(artifact, atype=ArtifactType.from_path(artifact), output_file=output_file)

    def prepare(
        manifest: Path = typer.Argument(
            sbomber.DEFAULT_MANIFEST,
            help="Path to a manifest file containing the required metadata.",
        ),
        statefile: Path = typer.Argument(
            sbomber.DEFAULT_STATEFILE,
            help="Path to statefile which will be created to hold the sbomber state.",
        ),
        pkg_dir: Path = typer.Option(
            sbomber.DEFAULT_PACKAGE_DIR,
            help="Folder where the collected artifacts will be gathered before uploading them.",
        ),
    ):
        """Gather all artifacts from the manifest and generate a statefile."""
        return sbomber.prepare(manifest=manifest, statefile=statefile, pkg_dir=pkg_dir)

    def submit(
        statefile: Path = typer.Argument(
            sbomber.DEFAULT_STATEFILE, help="Path to a statefile holding the sbomber state."
        ),
        pkg_dir: Path = typer.Option(
            sbomber.DEFAULT_PACKAGE_DIR,
            help="Folder where the collected artifacts will be gathered before uploading them.",
        ),
    ):
        """Submit all artifacts mentioned in the statefile."""
        return sbomber.submit(statefile=statefile, pkg_dir=pkg_dir)

    def poll(
        statefile: Path = typer.Argument(
            sbomber.DEFAULT_STATEFILE, help="Path to a statefile holding the sbomber state."
        ),
        wait: bool = typer.Option(
            False, is_flag=True, help="Wait for all sboms to be in Completed state before exiting."
        ),
        timeout: int = typer.Option(
            15, is_flag=True, help="Timeout (in minutes) for artifact completion (per artifact)."
        ),
    ):
        """Report the status of all clients on the artifacts you submitted."""
        exit_code = sbomber.poll(statefile=statefile, wait=wait, timeout=timeout)
        raise typer.Exit(code=exit_code)

    def download(
        statefile: Path = typer.Argument(
            sbomber.DEFAULT_STATEFILE, help="Path to a statefile holding the sbomber state."
        ),
        reports_dir: Path = typer.Option(
            sbomber.DEFAULT_REPORTS_DIR, help="Directory in which to drop all downloaded reports."
        ),
    ):
        """Download all completed reports."""
        return sbomber.download(statefile=statefile, reports_dir=reports_dir)

    app = typer.Typer(name="sbomber", no_args_is_help=True)
    sequential = typer.Typer(help="Sequential sbombing tools.", name="sequential")
    sequential.command(no_args_is_help=True)(sbom)
    sequential.command(no_args_is_help=True)(secscan)

    parallel = typer.Typer(help="Parallel sbombing tools.", no_args_is_help=True)
    parallel.command()(prepare)
    parallel.command()(submit)
    parallel.command()(poll)
    parallel.command()(download)

    app.add_typer(sequential, no_args_is_help=True)
    app.add_typer(parallel, no_args_is_help=True)

    app()


if __name__ == "__main__":
    main()
