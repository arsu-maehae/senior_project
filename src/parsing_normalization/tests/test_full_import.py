import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from evtx_pipeline import full_import
from evtx_pipeline import cli as cli_module
from evtx_pipeline.database import insert_scenario_run, insert_source_file
from evtx_pipeline.full_import import (_insert_batch, _row_values, publish_database, run_full_import,
                            validate_full_database, validate_publication_paths)
from evtx_pipeline.normalize import exact_duplicate_digest_from_event, normalize_event
from evtx_pipeline.schema import create_schema


def _event(rel, sha, channel, event_id, *, eventdata=None):
    return {"schema_version":"1.0","source":{"relative_path":rel,"sha256":sha,"size_bytes":16},
            "hints":{"claimed_scenario":"s01","host_from_path":"ep-01"},
            "system":{"event_id":event_id,"event_record_id":"1","channel":channel,
                      "computer":"EP-01.example.test","timestamp_raw":"2026-01-01T00:00:00Z"},
            "event_data":eventdata or [],"user_data":None,"raw_xml":"<Event/>"}


def _mini_collection(workspace: Path):
    input_root=workspace/"data"/"staging"/"evtx_jsonl_full"
    rows=[]
    definitions=[("Security",4624),("Sysmon",1),("System",7045),
                 ("PowerShell",4103),("WinRM",6),("Sysmon",1)]
    duplicate=None
    for i,(channel,event_id) in enumerate(definitions):
        rel=f"ep-01/dryrun_s01/{channel.lower()}_{i}.evtx"
        output_rel=f"per_file/{rel[:-5]}.jsonl"
        out=input_root/output_rel
        out.parent.mkdir(parents=True,exist_ok=True)
        sha=("b"*64) if i in (1,5) else hashlib.sha256(rel.encode()).hexdigest()
        eventdata=[{"name":"LogonGuid","value":"{12345678-1234-5678-9abc-def012345678}"}] if i==0 else None
        event=duplicate if i==5 else _event(rel,sha,channel,event_id,eventdata=eventdata)
        if i==1: duplicate=event
        else:
            event=_event(rel,sha,channel,event_id)
        # Duplicate rows differ only in Phase 1 provenance and must stay separate.
        if i==5:
            event=json.loads(json.dumps(duplicate))
            event["source"]["relative_path"]=rel
            event["source"]["sha256"]=sha
        out.write_text(json.dumps(event,separators=(",",":"))+"\n",encoding="utf-8")
        rows.append({"relative_path":rel,"size_bytes":16,"pre_run_sha256":sha,
                     "post_run_sha256":sha,"status":"ok","attempted_record_count":1,
                     "emitted_event_count":1,"parse_error_count":0,"output_relative_path":output_rel})
    (input_root/"parse_errors.jsonl").write_text("",encoding="utf-8")
    manifest={"run_mode":"full","totals":{"files":len(rows),"attempted_records":len(rows),
              "emitted_events":len(rows),"parse_errors":0},"selected_inputs":rows}
    (input_root/"manifest.json").write_text(json.dumps(manifest),encoding="utf-8")
    profile={"counts":{"events":len(rows)},"groups":{"channel_event_id":{"Security:4624":1}},
             "security_4624_guid_field_audit":{"event_count":1,"events_with_parseable_nonzero_guid":1,
                 "guid_named_field_occurrences":{"LogonGuid":1},
                 "parseable_nonzero_guid_values_by_field":{"LogonGuid":1}},
             "applicable_field_coverage":{"target_logon_guid":{"applicable_event_count":1,"usable_count":1}}}
    profile_path=workspace/"data"/"profiles"/"full_normalization_profile.json"
    profile_path.parent.mkdir(parents=True,exist_ok=True)
    profile_path.write_text(json.dumps(profile),encoding="utf-8")
    return input_root


def _mini_expected(monkeypatch):
    monkeypatch.setattr(full_import,"FULL_INPUT_FILE_COUNT",6)
    monkeypatch.setattr(full_import,"FULL_INPUT_EVENT_COUNT",6)
    monkeypatch.setattr(full_import,"EXPECTED_SCENARIOS",{"s01"})
    monkeypatch.setattr(full_import,"EXPECTED_HOSTS",{"ep-01"})
    monkeypatch.setattr(full_import,"EXPECTED_CHANNELS",{"Security","Sysmon","System","PowerShell","WinRM"})
    monkeypatch.setattr(full_import,"INSERT_BATCH_SIZE",2)


def test_full_mode_path_gate_and_no_overwrite(tmp_path):
    workspace=tmp_path
    input_root=workspace/"data"/"staging"/"evtx_jsonl_full"
    input_root.mkdir(parents=True)
    final=workspace/"data"/"processed"/"attack_path.sqlite3"
    final.parent.mkdir(parents=True)
    resolved=validate_publication_paths(input_root,final,workspace)
    assert resolved[0]==input_root.resolve()
    final.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        validate_publication_paths(input_root,final,workspace)
    final.unlink()
    Path(str(final)+".tmp").write_bytes(b"partial")
    with pytest.raises(FileExistsError):
        validate_publication_paths(input_root,final,workspace)


def test_full_cli_gate_uses_only_approved_paths(monkeypatch,capsys,tmp_path):
    workspace=tmp_path
    monkeypatch.setattr(cli_module,"__file__",str(workspace/"evtx_pipeline"/"cli.py"))
    (workspace/"data"/"staging"/"evtx_jsonl_full").mkdir(parents=True)
    input_root=workspace/"data"/"staging"/"evtx_jsonl_full"
    final=workspace/"data"/"processed"/"attack_path.sqlite3"
    called=[]
    def fake_run(inp,db,report,*,workspace,test_summary):
        called.append((inp,db,report))
        return {"validation":{"event_rows":0,"normalization_error_rows":0,
                "duplicate_exact_candidates":0,"duplicate_near_conflicts":0},
                "final_database":str(db),"report_path":str(report)}
    monkeypatch.setattr(cli_module,"run_full_import",fake_run)
    rc=cli_module.main(["normalize","--input",str(input_root),"--database",str(final),"--mode","full"])
    assert rc==0 and called
    assert called[0][0]==input_root.resolve()
    called.clear()
    rc=cli_module.main(["normalize","--input",str(input_root),"--database",str(final.parent/"wrong.sqlite3"),"--mode","full"])
    assert rc==1 and not called
    assert "Full database path" in capsys.readouterr().err


def test_preflight_requires_fresh_4624_audit(tmp_path,monkeypatch):
    _mini_expected(monkeypatch)
    input_root=_mini_collection(tmp_path)
    (tmp_path/"data"/"profiles"/"full_normalization_profile.json").unlink()
    final=tmp_path/"data"/"processed"/"attack_path.sqlite3"
    with pytest.raises(ValueError,match="Phase 2B full normalization profile"):
        full_import.preflight(input_root,final,tmp_path)


def test_bounded_batch_insert_rolls_back_on_failure():
    connection=sqlite3.connect(":memory:")
    create_schema(connection)
    rel="ep-01/dryrun_s01/a.evtx"; sha="a"*64
    source_id=hashlib.sha256((rel+"\0"+sha).encode()).hexdigest()
    insert_scenario_run(connection,{"run_id":"run","schema_version":"2.3.0","started_utc":"now","completed_utc":None,
        "input_root":"in","phase1_manifest_path":"manifest","sampling_rule":"test","input_file_count":1,
        "input_event_count":1,"inserted_event_count":0,"run_status":"loading","notes":None})
    insert_source_file(connection,{"source_file_id":source_id,"scenario_run_id":"run","relative_path":rel,
        "source_sha256":sha,"source_size_bytes":16,"channel":"Sysmon","host_hint":"ep-01","scenario_id":"s01",
        "phase1_status":"ok","selected_for_smoke":0})
    connection.commit()
    event=_event(rel,sha,"Sysmon",1)
    normalized=normalize_event(event)
    row=_row_values(normalized,exact_duplicate_digest_from_event(event))
    with pytest.raises(sqlite3.IntegrityError):
        _insert_batch(connection,[row,row])
    assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]==0
    connection.close()


def test_atomic_publication_refuses_overwrite(tmp_path):
    temp=tmp_path/"attack_path.sqlite3.tmp"; final=tmp_path/"attack_path.sqlite3"
    temp.write_bytes(b"database")
    publish_database(temp,final)
    assert final.read_bytes()==b"database" and not temp.exists()
    another=tmp_path/"again.tmp"; another.write_bytes(b"partial")
    with pytest.raises(FileExistsError):
        publish_database(another,final)
    assert another.exists() and final.read_bytes()==b"database"


def test_full_import_is_bounded_accounted_and_records_duplicates(tmp_path,monkeypatch):
    _mini_expected(monkeypatch)
    workspace=tmp_path
    input_root=_mini_collection(workspace)
    final=workspace/"data"/"processed"/"attack_path.sqlite3"
    report=workspace/"data"/"reports"/"phase2c_full_import_report.md"
    details=run_full_import(input_root,final,report,workspace=workspace,test_summary="mini-test")
    result=details["validation"]
    assert result["passed"]
    assert result["event_rows"]==6
    assert result["row_accounting"]["accounting_balanced"]
    assert result["duplicate_exact_candidates"]==1
    assert result["duplicate_near_conflicts"]==0
    assert details["maximum_batch_rows"]<=2
    assert final.exists() and not Path(str(final)+".tmp").exists()
    assert report.exists()
    con=sqlite3.connect(final)
    assert con.execute("SELECT COUNT(*) FROM events").fetchone()[0]==6
    assert con.execute("SELECT COUNT(*) FROM duplicate_events").fetchone()[0]==1
    assert con.execute("SELECT COUNT(*) FROM validation_results").fetchone()[0]>0
    con.close()


def test_full_database_validation_detects_missing_input_rows():
    connection=sqlite3.connect(":memory:")
    create_schema(connection)
    manifest={"totals":{"emitted_events":1}}
    result=validate_full_database(connection,manifest=manifest,run_id="missing")
    assert not result["passed"]
    assert not result["checks"]["event_row_count"]
    connection.close()

