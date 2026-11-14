# EVTX Parsing and Normalization

A component of a cross-host security event analysis project. It inventories Windows EVTX files, converts events to JSONL with provenance, and provides normalization and SQLite import code.

The implementation and full setup instructions are in [src/parsing_normalization](src/parsing_normalization/README.md). Source logs and generated output are not included in this repository.

## Setup

From the repository root, with Python 3.11+:

```
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[test]"
```

`pip install -e .` installs every package under `src/` (`gate`, `clock_offset`, `trial_window`, `stitch`, `answer_key`, `log_check`, `lab_common`, `data_layout`, `x10_validate`) and `evtx_pipeline` in editable mode, as defined in the root `pyproject.toml`. It replaces the separate install of `src/parsing_normalization`, so do not install that one as well. The pipeline commands then run from the repository root, for example `python -m gate --help`, `python -m clock_offset --help`, `python -m trial_window --help` and `python -m stitch.check_links --help`. Run the tests with `python -m pytest`.

The full-import workflow was built for a specific dataset and is not a general-purpose importer. See the component README for its constraints, data links, commands and tests.
