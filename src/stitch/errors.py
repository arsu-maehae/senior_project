"""The one exception of the stitcher (spec 03_stitch section 2: refused inputs).

WHY a module of its own: ``inputs`` (file checks) and ``scan`` (pure row pass) both raise it, and ``scan``
must not import ``inputs`` (that would pull file-reading code into a pure module).
"""
from __future__ import annotations


class StitchError(Exception):
    """Refusal or input error that stops the stitcher before anything is written (ST-00, spec 2).

    WHY one type: a CLI maps it to one exit code with the reason, and a test can assert that nothing was
    written whatever the cause (allowlist, missing gate file, hash mismatch, bad event time).
    """
