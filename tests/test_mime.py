import mimetypes

import pytest

from clients.sbom import SBOMber  # noqa

# on sbom import, we register the mimetype mappings


@pytest.mark.parametrize(
    "filename, expected_mimetype",
    (
        ("foo.rock", "application/x-tar"),
        ("foo.charm", "application/zip"),
        ("foo.snap", "application/octet-stream"),
        ("foo.whl", "application/octet-stream"),
        ("foo.tar.gz", "application/x-tar"),
    ),
)
def test_mime(filename, expected_mimetype):
    mimetype, _ = mimetypes.guess_type(filename)
    assert mimetype == expected_mimetype
