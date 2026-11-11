"""Read-only x10 design validator (decision 029; quarantine per decision 030).

WHY a separate package: decision 029 ("Consequences") requires the validator to be independent of
the answer key, of the log-check link results and of any stitcher, so a trial is judged against the
design without re-using the code whose output the trials will later be scored with. It therefore
imports only the standard library and re-implements the few queries it needs.
"""
