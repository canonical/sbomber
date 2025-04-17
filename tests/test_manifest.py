from sbomber import DEFAULT_MANIFEST
from state import Manifest, SecScanClient


def test_manifest_load(tmp_path):
    manifest = """
    clients:
      secscan: {}

    artifacts:
      - name: foo-k8s-local
        source: /foo/charm.charm
        type: charm

      - name: bar-k8s.rock
        source: /bar/rock.rock
        type: rock

      - name: baz-k8s
        channel: latest/edge
        base: ubuntu@22.04
        type: charm

      - name: qux-rock
        image: ubuntu/qux
        version: 0-24.04
        type: rock

      - name: quq-deb
        package: quq
        type: deb
        base: noble
        arch: amd64
        pocket: main
        ppa: ppa:ubuntu/ppa
    """

    manifest_path = tmp_path / DEFAULT_MANIFEST
    manifest_path.write_text(manifest)
    meta = Manifest.load(manifest_path)
    clients = meta.clients

    assert not clients.sbom
    assert clients.secscan == SecScanClient()

    artifacts = meta.artifacts
    assert len(artifacts) == 5
    assert {a.name for a in artifacts} == {
        "foo-k8s-local",
        "bar-k8s.rock",
        "baz-k8s",
        "qux-rock",
        "quq-deb",
    }
    assert {a.channel for a in artifacts} == {None, "latest/edge"}
    assert {a.base for a in artifacts} == {None, "ubuntu@22.04", "noble"}
    assert {a.type for a in artifacts} == {"charm", "rock", "deb"}
    assert {a.version for a in artifacts} == {None, "0-24.04"}
    assert {a.package for a in artifacts} == {None, "quq"}
    assert {a.arch for a in artifacts} == {None, "amd64"}
    assert {a.pocket for a in artifacts} == {None, "main"}
    assert {a.ppa for a in artifacts} == {None, "ppa:ubuntu/ppa"}
