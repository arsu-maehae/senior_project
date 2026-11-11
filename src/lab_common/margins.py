"""Time margins around an agent run, in seconds (decisions 026 and 041).

WHY a neutral module: the draft key builder and the trial window step must use the same
60 s / 300 s margins (decision 026). Keeping them here gives one source for both, so they cannot
drift apart, and the pipeline (window step, gate) can read them without importing the key
builder's own modules (decision 041, spec 02_gate GTT-14).
"""
from __future__ import annotations

# Key window: earliest key event - 60 s .. latest key event + 300 s (decision 026).
KEY_MARGIN_BEFORE_S: float = 60.0
KEY_MARGIN_AFTER_S: float = 300.0

# Agent run interval / trial window: first agent root - 60 s .. last agent step + 300 s (decision 026).
RUN_INTERVAL_BEFORE_S: float = 60.0
RUN_INTERVAL_AFTER_S: float = 300.0
