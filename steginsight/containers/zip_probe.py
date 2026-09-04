"""Verify that a candidate region really is a ZIP archive.

Matching ``PK\\x03\\x04`` proves nothing on its own — those four bytes occur by
chance roughly once per 4 GB of random data, and compressed image data is
effectively random. Actually opening the archive and listing its entries turns
a lead into proof, which is the difference between a finding an analyst can act
on and one they have to go and check by hand.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass

__all__ = ["ZipProbe", "probe_zip"]

#: Cap on entries listed; a zip bomb should not be able to exhaust memory here.
MAX_ENTRIES = 512


@dataclass(frozen=True, slots=True)
class ZipProbe:
    names: list[str]
    total_uncompressed: int
    encrypted: bool
    comment: bytes


def probe_zip(data: bytes) -> ZipProbe | None:
    """Return archive contents if ``data`` opens as a ZIP, else ``None``."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()[:MAX_ENTRIES]
            if not infos:
                # An empty-but-valid archive is still a valid archive.
                return ZipProbe([], 0, False, archive.comment or b"")
            return ZipProbe(
                names=[i.filename for i in infos],
                total_uncompressed=sum(i.file_size for i in infos),
                # Bit 0 of the general-purpose flag marks an encrypted entry.
                encrypted=any(i.flag_bits & 0x1 for i in infos),
                comment=archive.comment or b"",
            )
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError):
        return None
