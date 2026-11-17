"""Score stage (spec 05_score; PLAN T9): rank every stitch candidate path by w1*LengthScore + w2*NodeScore +
w3*IdentityCoherence, with the baselines b1, b2 and b0. ``python -m score --trial <t> | --development``.

Inputs: ``out/stitch/<t>/`` and ``out/label/<t>/`` (never ``ground_truth/`` or ``data/``, SC-03); output:
``out/score/<t>/``. The score orders paths; it is not a likelihood and no threshold is applied (Correction J).
"""
