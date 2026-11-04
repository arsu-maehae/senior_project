# EVTX parsing and normalization

This repository contains the Phase 1 EVTX-to-JSONL converter and the Phase 2 normalization and SQLite code. It excludes the event collection and generated artifacts.

## Project data

The source collection and database are hosted on Google Drive. Access depends on the Drive sharing permissions; links do not grant access by themselves.

- [Source EVTX collection (full_collection)](https://drive.google.com/drive/folders/1W2gd4sIYXnFoPjR9Jq2ZqiuJKiRNf6Qv)
- [Data folder](https://drive.google.com/drive/folders/1PaOftpJQFeg7F_Sa_W7SFNUaQSEohMaB)
- [Normalized SQLite database (attack_path.sqlite3, 17,369,427,968 bytes)](https://drive.google.com/file/d/1mYOcXwWmzUUEH0Vre6IO6ZshydbdsHMj/view?usp=sharing)

To query the existing database locally, download it to `data/processed/attack_path.sqlite3` under this project directory and open it with a SQLite client. Keep the downloaded source EVTX collection in a separate input directory.

The linked data folder was observed to contain the SQLite database. The Phase 1 JSONL output, conversion manifest, parse-error file, and normalization profile are not confirmed available at these links; the existing full-import command requires its Phase 1 input and profile, as described below.

## Setup

Python 3.11 or newer and the `evtx` package are required. On Windows, from this directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m pip install pytest
python -m pytest
```

## Parsing

Choose separate input and new output directories. The input contains EVTX files; the output contains JSONL, a manifest, and parse errors.

```powershell
python -m evtx_pipeline.cli convert --input "C:\path\to\evtx" --output "C:\path\to\new_jsonl_output"
python -m evtx_pipeline.cli validate --input "C:\path\to\evtx" --output "C:\path\to\new_jsonl_output"
```

`inventory` is also available; `python -m evtx_pipeline.cli --help` lists options. The converter uses an EVTX signature check and writes one JSON object per event, including source provenance and the parser-produced XML. Legacy binary EVT files are not supported. Conversion `--smoke` selects three EVTX-compatible files of at most 100 MiB and excludes files named Security; it fails if fewer than three eligible files are available. EVTX input and generated output are not included in this repository.

## Normalization and SQLite

`evtx_pipeline/normalize.py` normalizes individual Phase 1 event objects; `evtx_pipeline/schema.py` defines SQLite tables and indexes; `evtx_pipeline/database.py`, `evtx_pipeline/smoke_import.py`, and `evtx_pipeline/full_import.py` implement storage and import. The original JSON and decoded XML are retained in the event's `raw_event`.

The existing `normalize` and `profile-normalization` commands were designed for the original project run. They enforce workspace-relative paths, and the full import requires the original manifest, profile, expected 85 files and 2,981,147 events. The full importer refuses an existing target database. **They are not a general-purpose importer for arbitrary new datasets.** Supporting those requires further implementation and validation.

```powershell
python -m evtx_pipeline.cli normalize --help
python -m evtx_pipeline.cli profile-normalization --help
```

The remaining full-import tests use synthetic records; they do not include the original dataset. Dedicated parser and normalization tests are not included. Install `pytest` separately as shown above.

