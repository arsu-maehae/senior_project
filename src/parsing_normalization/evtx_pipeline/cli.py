from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .decoder import convert, validate
from .inventory import inventory_json, reject_overlap
from .smoke_import import run_smoke
from .profile import run_profile, render_report
from .full_import import run_full_import


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m evtx_pipeline.cli")
    sub = parser.add_subparsers(dest="operation", required=True)
    inv = sub.add_parser("inventory")
    inv.add_argument("--input", required=True, type=Path)
    inv.add_argument("--output", required=True, type=Path)
    conv = sub.add_parser("convert")
    conv.add_argument("--input", required=True, type=Path)
    conv.add_argument("--output", required=True, type=Path)
    conv.add_argument("--smoke", action="store_true")
    conv.add_argument("--overwrite", action="store_true")
    val = sub.add_parser("validate")
    val.add_argument("--input", required=True, type=Path)
    val.add_argument("--output", required=True, type=Path)
    norm = sub.add_parser("normalize", help="Phase 2A normalized SQLite import")
    norm.add_argument("--input", required=True, type=Path)
    norm.add_argument("--database", required=True, type=Path)
    norm.add_argument("--mode", choices=("smoke", "full"), required=True)
    norm.add_argument("--test-summary", default="Not recorded")
    profile = sub.add_parser("profile-normalization", help="Stream Phase 1 JSONL and profile normalization readiness")
    profile.add_argument("--input", required=True, type=Path)
    profile.add_argument("--output", required=True, type=Path)
    profile.add_argument("--test-summary", default="Not recorded")
    profile.add_argument("--overwrite", action="store_true", help="Replace only existing Phase 2B profile outputs")
    trial = sub.add_parser("import-trial", help="Import one trial's Phase 1 JSONL into a per-trial SQLite file")
    trial.add_argument("--jsonl", required=True, type=Path)
    trial.add_argument("--scenario", required=True)
    trial.add_argument("--trial", required=True)
    trial.add_argument("--database", required=True, type=Path)
    trial.add_argument("--report-dir", type=Path, default=Path("out/normalise"))
    args = parser.parse_args(argv)
    try:
        if args.operation == "import-trial":
            from .trial_import import run_trial_import
            result = run_trial_import(args.jsonl, args.scenario, args.trial, args.database, args.report_dir)
            print(f"import-trial PASS: {result['events']:,} events; {result['events_dedup']:,} in events_dedup; "
                  f"{result['duplicates_exact']:,} exact / {result['duplicates_near']:,} near duplicates; "
                  f"{result['duration_seconds']}s ({result['events_per_second']} events/s)")
            print(f"Database: {result['database']}")
            return 0
        if args.operation == "inventory":
            reject_overlap(args.input, args.output.parent)
            data = inventory_json(args.input)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            if args.output.exists():
                raise FileExistsError(args.output)
            args.output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"Inventory: {len(data['files'])} files -> {args.output}")
        elif args.operation == "convert":
            result = convert(args.input, args.output, args.smoke, args.overwrite,
                             " ".join(["python", "-m", "evtx_pipeline.cli", *(argv if argv is not None else sys.argv[1:])]))
            print(f"Converted {result['totals']['files']} files; {result['totals']['emitted_events']} events; {result['totals']['parse_errors']} parse errors")
            if result["failures"] or result["totals"]["parse_errors"]:
                return 1
        elif args.operation == "profile-normalization":
            workspace = Path(__file__).resolve().parent.parent
            expected_input = workspace / "data" / "staging" / "evtx_jsonl_full"
            expected_output = workspace / "data" / "profiles" / "full_normalization_profile.json"
            expected_report = workspace / "data" / "reports" / "phase2b_full_profile_report.md"
            input_path = args.input.resolve(strict=True)
            output_path = args.output.resolve()
            if input_path != expected_input.resolve(strict=True):
                raise ValueError(f"Profile input must be the immutable Phase 1 output: {expected_input}")
            if output_path != expected_output.resolve():
                raise ValueError(f"Profile JSON must be written to: {expected_output}")
            if (output_path.exists() or expected_report.exists()) and not args.overwrite:
                raise FileExistsError("Refusing to overwrite an existing Phase 2B profile or report.")
            result = run_profile(input_path)
            result["profile_path"] = str(output_path)
            result["report_path"] = str(expected_report)
            result["test_result"] = args.test_summary
            output_path.parent.mkdir(parents=True, exist_ok=True)
            expected_report.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            expected_report.write_text(render_report(result, test_result=args.test_summary), encoding="utf-8")
            print(f"Profiled {result['counts']['events']:,} events; profile: {output_path}")
            print(f"Report: {expected_report}")
            return 0
        else:
            if args.operation == "validate":
                result = validate(args.input, args.output)
                print(f"Validation {'PASS' if result['passed'] else 'FAIL'}: {result['validated_files']} files, {result['emitted_events']} events")
                for issue in result["issues"][:20]: print(f"- {issue}")
                return 0 if result["passed"] else 1
            workspace = Path(__file__).resolve().parent.parent
            expected_input = workspace / "data" / "staging" / "evtx_jsonl_full"
            expected_database = workspace / "data" / "processed" / "attack_path_smoke.sqlite3"
            input_path = args.input.resolve(strict=True)
            database_path = args.database.resolve()
            if input_path != expected_input.resolve(strict=True):
                raise ValueError(f"Normalization input must be the immutable Phase 1 output: {expected_input}")
            if args.mode == "full":
                final_database = workspace / "data" / "processed" / "attack_path.sqlite3"
                if database_path != final_database.resolve():
                    raise ValueError(f"Full database path must be inside the approved workspace at: {final_database}")
                report_path = workspace / "data" / "reports" / "phase2c_full_import_report.md"
                result = run_full_import(input_path, database_path, report_path, workspace=workspace,
                                         test_summary=args.test_summary)
                print(f"Full import PASS: {result['validation']['event_rows']:,} events; "
                      f"{result['validation']['normalization_error_rows']:,} normalization-error rows; "
                      f"{result['validation']['duplicate_exact_candidates']:,} exact duplicate candidates; "
                      f"{result['validation']['duplicate_near_conflicts']:,} near-duplicate conflicts")
                print(f"Database: {result['final_database']}")
                print(f"Report: {result['report_path']}")
                return 0
            if database_path != expected_database.resolve():
                raise ValueError(f"Phase 2A smoke database must be inside the approved workspace at: {expected_database}")
            result = run_smoke(input_path, database_path, args.test_summary)
            print(f"Phase 2A smoke PASS: {result['counts']['events']} sample events; "
                  f"{result['counts']['normalization_errors']} normalization warnings; "
                  f"{result['counts']['duplicate_candidates']} duplicate candidates; "
                  f"{result['validation']['readiness_status']}")
            print(f"Database: {result['database_path']}")
            print(f"Report: {result['report_path']}")
            return 0
        return 0
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {str(exc)[:500]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

