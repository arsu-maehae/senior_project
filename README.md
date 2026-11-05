# EVTX Parsing and Normalization

A component of a cross-host security event analysis project. It inventories Windows EVTX files, converts events to JSONL with provenance, and provides normalization and SQLite import code.

The implementation and full setup instructions are in [src/parsing_normalization](src/parsing_normalization/README.md). Source logs and generated output are not included in this repository.

The full-import workflow was built for a specific dataset and is not a general-purpose importer. See the component README for its constraints, data links, commands and tests.
