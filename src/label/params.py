"""Parameters and constants of the labeller (spec 04_label sections 2, 3.1, 3.5, 4 and 5; decisions 056, 057).

WHY one module: every value the labeller depends on (the SigmaHQ commit, the level map, the locked rule table, the
time tolerances it borrows) is visible in one place and is written into ``run_info.json``. Values another stage
already defines (development allowlist, process-collapse window, service-pair tolerance) are imported, never copied,
so the labeller cannot disagree with the stitcher or the gate (spec 5: "one definition").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from gate.params import GateParams
from stitch.params import ALLOWED_TRIALS, StitchParams

__all__ = ["TOOL_VERSION", "VIEW", "METHOD", "LABEL_OUT_REL", "STITCH_OUT_REL", "RULES_DIR", "MANIFEST_FILE",
           "SIGMA_COMMIT", "LEVEL_VALUE", "OWN_RULE_LEVEL", "SOURCE_SIGMAHQ", "SOURCE_OWN", "LICENSE_DRL",
           "LICENSE_OWN", "MANIFEST_COLUMNS", "RuleEntry", "RULE_TABLE", "RULE_SHA256", "MANIFEST_SHA256",
           "STITCH_FILES", "STITCH_CSV_COLUMNS", "DB_COLUMNS", "ALLOWED_TRIALS", "LabelParams"]

TOOL_VERSION = "label 0.1.0"
VIEW = "events_dedup"
METHOD = "sigma_rule"                      # spec 3.4: the ``method`` of every label row

LABEL_OUT_REL = "out/label"
STITCH_OUT_REL = "out/stitch"
RULES_DIR: Path = Path(__file__).resolve().parent / "rules"
MANIFEST_FILE = "manifest.csv"

# Spec 5: the SigmaHQ state the list was taken from (decision 056).
SIGMA_COMMIT = "54967d64e6dda2b4daa81f47f7a8bf1f591b68a0"

# Spec 5 / Correction G: the locked Sigma level map; a rule with any other level is refused (spec 2).
LEVEL_VALUE: Mapping[str, int] = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
OWN_RULE_LEVEL = "low"                     # LB-07, Q5 (a)

SOURCE_SIGMAHQ, SOURCE_OWN = "sigmahq", "own"
LICENSE_DRL, LICENSE_OWN = "DRL-1.1", "own"

# Spec 3.4 ``rules_manifest.csv`` columns, in spec order (also the columns of ``rules/manifest.csv``).
MANIFEST_COLUMNS: tuple[str, ...] = (
    "rule_id", "file", "sha256", "source", "sigma_id", "sigma_commit", "title", "author", "license", "references",
    "technique", "techniques", "tactics", "level",
)


@dataclass(frozen=True)
class RuleEntry:
    """One row of the locked list (spec 3.5) as far as the YAML file cannot say it itself.

    WHY here and not in the YAML: the primary technique and the SigmaHQ origin are project facts (spec 3.1), and
    an adapted rule's file carries its NEW id, so the original SigmaHQ id must be stated by us.
    """
    rule_id: str
    file: str
    source: str
    technique: str
    sigma_id: str = ""          # original SigmaHQ id ("" for an own rule); for SR-10 the id it was derived from
    sigma_path: str = ""        # path in the SigmaHQ repository at SIGMA_COMMIT
    adapted: bool = False       # SR-10, decision 056 P1


# Decision 056 / spec 3.5: the 14 locked rules. Changing this table needs a new decision record (LB-10).
RULE_TABLE: tuple[RuleEntry, ...] = (
    RuleEntry("SR-01", "SR-01_lsass_dump_comsvcs_dll.yml", SOURCE_SIGMAHQ, "T1003.001",
              "a49fa4d5-11db-418c-8473-1e014a8dd462",
              "rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml"),
    RuleEntry("SR-02", "SR-02_lsass_memdump.yml", SOURCE_SIGMAHQ, "T1003.001",
              "5ef9853e-4d0e-4a70-846f-a9ca37d876da",
              "rules/windows/process_access/proc_access_win_lsass_memdump.yml"),
    RuleEntry("SR-03", "SR-03_lsass_remote_access_winrm.yml", SOURCE_SIGMAHQ, "T1003.001",
              "aa35a627-33fb-4d04-a165-d33b4afca3e8",
              "rules/windows/process_access/proc_access_win_lsass_remote_access_trough_winrm.yml"),
    RuleEntry("SR-10", "SR-10_admin_share_access.yml", SOURCE_SIGMAHQ, "T1021.002",
              "098d7118-55bc-4912-a836-dc6483a8d150",
              "rules/windows/builtin/security/win_security_admin_share_access.yml", adapted=True),
    RuleEntry("SR-11", "SR-11_smb_file_creation_admin_shares.yml", SOURCE_SIGMAHQ, "T1021.002",
              "b210394c-ba12-4f89-9117-44a2464b9511",
              "rules/windows/builtin/security/win_security_smb_file_creation_admin_shares.yml"),
    RuleEntry("SR-12", "SR-12_svcctl_remote_service.yml", SOURCE_SIGMAHQ, "T1021.002",
              "586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3",
              "rules/windows/builtin/security/win_security_svcctl_remote_service.yml"),
    RuleEntry("SR-20", "SR-20_executable_written_admin_share.yml", SOURCE_OWN, "T1570"),
    RuleEntry("SR-30", "SR-30_service_installed_system.yml", SOURCE_OWN, "T1569.002"),
    RuleEntry("SR-31", "SR-31_service_installed_security.yml", SOURCE_OWN, "T1569.002"),
    RuleEntry("SR-40", "SR-40_winrm_remote_powershell_session_process.yml", SOURCE_SIGMAHQ, "T1021.006",
              "734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8",
              "rules/windows/process_creation/proc_creation_win_winrm_remote_powershell_session_process.yml"),
    RuleEntry("SR-41", "SR-41_susp_remote_powershell_session.yml", SOURCE_SIGMAHQ, "T1021.006",
              "c539afac-c12a-46ed-b1bd-5a5567c9f045",
              "rules/windows/network_connection/net_connection_win_susp_remote_powershell_session.yml"),
    RuleEntry("SR-50", "SR-50_rdp_logon.yml", SOURCE_OWN, "T1021.001"),
    RuleEntry("SR-60", "SR-60_susp_logon_explicit_credentials.yml", SOURCE_SIGMAHQ, "T1078",
              "941e5c45-cda7-4864-8cea-bbb7458d194a",
              "rules/windows/builtin/security/win_security_susp_logon_explicit_credentials.yml"),
    RuleEntry("SR-61", "SR-61_pass_the_hash_2.yml", SOURCE_SIGMAHQ, "T1550.002",
              "8eef149c-bd26-49f2-9e5a-9b00e3af499b",
              "rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml"),
)

# LB-10 lock pinned in code (stage review S01; decisions 056, 059, 061). The LF SHA-256 (LB-13) of every locked rule
# file and of ``rules/manifest.csv``. WHY literals here and not only the manifest: the manifest is recomputed from
# the same files, so on its own it pins nothing; a changed rule file plus a rewritten manifest would still load. With
# these literals a rule change is refused until this table is changed too, which needs a new decision record.
RULE_SHA256: Mapping[str, str] = {
    "SR-01": "e21fdafd9ae62edb6a1e56626098962446db0116b7d74c65390e2004f9b6eea1",
    "SR-02": "685d4e6de0d8644006aea0a333d155f8053e8fd545a211003c608cc2a633a952",
    "SR-03": "aa5a9efa0c5fe4e3b65d26433eb163293706c08bd14579161ca4eaf41dcd8729",
    "SR-10": "ea4c7616dc2668960a7f90be68bd14bac6f8918146bf3caa3c1f03989f027cb4",
    "SR-11": "48965a503ddb84bd0f98b9215467e1ac5b83caaf40cda976b154e108efdec368",
    "SR-12": "8b0320e5467b94d464f5212a363a72cebfdfb6ce3bfa36d2c43c8bc9b6ed3171",
    "SR-20": "570444935014e6040f59809e0ccd5932e149240dade4cca2fcabe3d36dca1532",
    "SR-30": "bb8fdfdf290358e91a0268f5a1df2b4d81c5189395df5c7a65a612edd5b87c04",
    "SR-31": "1358bda73b3fa08a6738afa1d44abb1d2dcbd52c1142b9c3ae693f4948dd348f",
    "SR-40": "fc874778dd8be01110ead523c56b7892206daf981152fa40371f3a2b9741f1a1",
    "SR-41": "d6e78042bab06777df640416fa2d62e6906f28fa155e09b115de1674cbcadc59",
    "SR-50": "5a05e9aacee626c8a139c30bccb1ebba710c7514590e0874dc601ac8f2d9eb32",
    "SR-60": "abc7123f2e21d4bf6fc90711885f68478d253993b360897fa00d6a27c3a903bb",
    "SR-61": "a60b80c34a90e086dc1a394b8bc2c252684d17fec99c37939f8a9f43a958f1b7",
}
MANIFEST_SHA256 = "3508a065dad556d0aad214470270dc4868759c4b023b3454febfb1d45288ee5e"

# Spec 2: the stitch outputs the node join reads; every one must exist.
STITCH_FILES: tuple[str, ...] = ("path_nodes.csv", "hops.csv", "hop_artefacts.csv", "hop_identity.csv",
                                 "run_info.json")
# The columns the join reads from each stitch CSV (spec 03 section 3); a file lacking one is refused (stage review
# S05 c), so a missing column can never turn into silent empty values. hop_artefacts.csv is read and hashed only.
STITCH_CSV_COLUMNS: Mapping[str, tuple[str, ...]] = {
    "path_nodes.csv": ("path_id", "hop_id", "role", "context", "host", "event_uid"),
    "hops.csv": ("hop_id", "in_path", "member_logon_uids"),
    "hop_artefacts.csv": ("hop_id",),
    "hop_identity.csv": ("hop_id", "dump_event_uid", "dump_utc_corrected"),
}

# Spec 2 columns of ``events_dedup``, plus ``process_id`` and ``service_name``: the two keys of the LB-11 pairings
# (spec 03 ST-11 pairs Sysmon 1 / 4688 by ``process_id``; 02_gate GT-12 pairs 4697 / 7045 by ``service_name``).
# WHY no ``command_line`` column: rules read command text only inside ``field_values_json``, which is parsed in
# memory and never written (LB-09).
DB_COLUMNS: tuple[str, ...] = ("event_uid", "host", "channel", "event_id", "record_id", "event_utc",
                               "field_values_json", "account_name", "machine_account", "process_id", "service_name")

_STITCH = StitchParams()
_GATE = GateParams()


@dataclass(frozen=True)
class LabelParams:
    """Spec section 5 values. ``process_collapse_s`` and ``service_pair_s`` are the stitcher's and the gate's own
    values (LB-11 "as spec 03 ST-11" / "as 02_gate GT-12"), read from their parameter classes."""
    sigma_commit: str = SIGMA_COMMIT
    level_value: Mapping[str, int] = field(default_factory=lambda: dict(LEVEL_VALUE))
    own_rule_level: str = OWN_RULE_LEVEL
    process_collapse_s: float = _STITCH.process_collapse_s
    service_pair_s: float = _GATE.service_pair_s
