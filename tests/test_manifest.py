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
    """

    manifest_path = tmp_path / DEFAULT_MANIFEST
    manifest_path.write_text(manifest)
    meta = Manifest.load(manifest_path)
    clients = meta.clients

    assert not clients.sbom
    assert clients.secscan == SecScanClient()

    artifacts = meta.artifacts
    assert len(artifacts) == 4
    assert {a.name for a in artifacts} == {"foo-k8s-local", "bar-k8s.rock", "baz-k8s", "qux-rock"}
    assert {a.channel for a in artifacts} == {None, "latest/edge"}
    assert {a.base for a in artifacts} == {None, "ubuntu@22.04"}
    assert {a.type for a in artifacts} == {"charm", "rock"}
    assert {a.version for a in artifacts} == {None, "0-24.04"}
