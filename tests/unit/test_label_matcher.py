"""T8.2d: the Sigma subset matcher and the rule-file loader refusals (spec 04_label LBT-03, LBT-04, LB-04, LB-05, LB-12).

Written from the spec and decisions 056 / 057 / 058, not from the implementation (the code was read only for its public
entry points). Pure unit tests on synthetic values: nothing real is opened, nothing is written.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from label import matcher as mt  # noqa: E402
from label.errors import LabelError  # noqa: E402
from label.params import RuleEntry  # noqa: E402
from label.rules import parse_rule  # noqa: E402


def det(selection: dict | list, condition: str = "selection", **more) -> mt.Detection:
    block = {"selection": selection, "condition": condition}
    block.update(more)
    return mt.compile_detection(block)


def fields(**kw) -> dict:
    return mt.event_fields(kw)


def hit(d: mt.Detection, f: dict, p4688: bool = False) -> bool:
    return mt.match_detection(d, f, p4688)


# ================================================================================================ LBT-03 field mapping
def test_field_key_is_the_lower_case_name():
    assert mt.field_key("TargetImage") == "targetimage"
    assert mt.field_key("GrantedAccess") == "grantedaccess"
    assert mt.field_key("EventID") == "eventid"


def test_provider_name_maps_to_provider():
    assert mt.field_key("Provider_Name") == "provider"


def test_4688_renames_apply_only_to_process_creation_on_4688():
    assert mt.field_key("Image", True) == "newprocessname"
    assert mt.field_key("ParentImage", True) == "parentprocessname"
    assert mt.field_key("CommandLine", True) == "commandline"
    assert mt.field_key("Image", False) == "image"
    assert mt.field_key("ParentImage", False) == "parentimage"


def test_original_file_name_has_no_4688_field_and_never_matches():
    assert mt.field_key("OriginalFileName", True) is None
    d = det({"OriginalFileName": "wsmprovhost.exe"})
    assert hit(d, fields(originalfilename=["wsmprovhost.exe"]), True) is False
    assert hit(d, fields(originalfilename=["wsmprovhost.exe"]), False) is True       # a Sysmon 1 field is fine


def test_4688_uses_the_renamed_fields_and_not_the_sysmon_names():
    d = det({"Image|endswith": r"\wsmprovhost.exe"})
    assert hit(d, fields(newprocessname=[r"C:\Windows\System32\wsmprovhost.exe"]), True)
    assert not hit(d, fields(image=[r"C:\Windows\System32\wsmprovhost.exe"]), True)
    assert hit(d, fields(image=[r"C:\Windows\System32\wsmprovhost.exe"]), False)
    assert not hit(d, fields(newprocessname=[r"C:\Windows\System32\wsmprovhost.exe"]), False)


def test_event_field_keys_are_lower_cased_and_one_element_lists_unwrapped():
    f = mt.event_fields({"TargetImage": ["C:\\x.exe"], "Scalar": "v"})
    assert set(f) == {"targetimage", "scalar"}
    assert tuple(f["targetimage"]) == ("C:\\x.exe",)
    assert tuple(f["scalar"]) == ("v",)


def test_a_list_of_several_values_matches_when_any_element_matches():
    d = det({"Port": "5985"})
    assert hit(d, fields(port=["80", "5985"]))
    assert hit(d, fields(port=["5985", "80"]))
    assert not hit(d, fields(port=["80", "443"]))


def test_a_null_field_is_absent_decision_058():
    """058 point 6: `[null]` is absent, never the text "None" or an empty string."""
    f = mt.event_fields({"x": [None], "y": [], "z": ["v"]})
    assert "x" not in f and "y" not in f and "z" in f
    assert not hit(det({"X|contains": "one"}), fields(x=[None]))
    assert not hit(det({"X|contains": "ne"}, "selection"), fields(x=[None]))
    # absent also makes a filter false, so `not filter` holds
    d = det({"A": "1"}, "selection and not filter", filter={"X|endswith": ""})
    assert hit(d, fields(a=["1"], x=[None]))


def test_missing_field_never_matches_a_selection_item():
    d = det({"A": "1", "B": "2"})
    assert not hit(d, fields(a=["1"]))
    assert not hit(d, fields(b=["2"]))
    assert hit(d, fields(a=["1"], b=["2"]))


def test_missing_field_makes_a_filter_false_so_the_rule_still_matches():
    d = det({"A": "1"}, "selection and not filter", filter={"B": "bad"})
    assert hit(d, fields(a=["1"]))                                   # B absent: filter false
    assert hit(d, fields(a=["1"], b=["fine"]))
    assert not hit(d, fields(a=["1"], b=["bad"]))


def test_matching_is_case_insensitive_on_both_sides():
    d = det({"Image|endswith": r"\LSASS.EXE"})
    assert hit(d, fields(image=[r"c:\windows\system32\lsass.exe"]))
    assert hit(det({"Name": "AbC"}), fields(name=["aBc"]))


def test_integer_rule_value_compares_as_decimal_text():
    d = det({"LogonType": 10})
    assert hit(d, fields(logontype=["10"]))
    assert not hit(d, fields(logontype=["3"]))
    assert not hit(d, fields(logontype=["100"]))


def test_wildcards_star_and_question_mark():
    assert hit(det({"V": "a*c"}), fields(v=["abbbc"]))
    assert hit(det({"V": "a*c"}), fields(v=["ac"]))
    assert not hit(det({"V": "a*c"}), fields(v=["abbbd"]))
    assert hit(det({"V": "a?c"}), fields(v=["abc"]))
    assert not hit(det({"V": "a?c"}), fields(v=["ac"]))
    assert not hit(det({"V": "a?c"}), fields(v=["abbc"]))


def test_equals_is_a_full_match_not_a_substring():
    d = det({"V": "abc"})
    assert hit(d, fields(v=["abc"]))
    assert not hit(d, fields(v=["abcd"]))
    assert not hit(d, fields(v=["xabc"]))


# ================================================================================================ LB-12 escapes
def test_escaped_star_and_question_are_literal():
    assert hit(det({"V": r"a\*c"}), fields(v=["a*c"]))
    assert not hit(det({"V": r"a\*c"}), fields(v=["abc"]))
    assert hit(det({"V": r"a\?c"}), fields(v=["a?c"]))
    assert not hit(det({"V": r"a\?c"}), fields(v=["abc"]))


def test_double_backslash_is_one_backslash_and_other_backslashes_are_literal():
    assert hit(det({"V": r"a\\b"}), fields(v=["a\\b"]))
    assert hit(det({"V": r"C:\Windows\x"}), fields(v=[r"C:\Windows\x"]))           # \W and \x stay literal
    assert not hit(det({"V": r"C:\Windows\x"}), fields(v=[r"C:Windowsx"]))


def test_backslash_then_star_wildcard():
    """`\\\\*` is a backslash and then an unescaped wildcard (left-to-right scan)."""
    d = det({"V": r"a\\*"})
    assert hit(d, fields(v=["a\\bcd"]))
    assert hit(d, fields(v=["a\\"]))
    assert not hit(d, fields(v=["abcd"]))


def test_stored_share_name_with_a_literal_star_matches_the_endswith_literal():
    d = det({"ShareName|endswith": r"\ADMIN$"})
    assert hit(d, fields(sharename=[r"\\*\ADMIN$"]))
    assert not hit(d, fields(sharename=[r"\\*\IPC$"]))


def test_literal_star_in_a_rule_value_matches_only_a_stored_star():
    d = det({"ShareName": r"\\\\\*\\IPC$"})                                         # the SR-12 spelling
    assert hit(d, fields(sharename=[r"\\*\IPC$"]))
    assert not hit(d, fields(sharename=[r"\\HOST\IPC$"]))


def test_trailing_backslash_is_literal():
    d = det({"V|endswith": "dir\\"})
    assert hit(d, fields(v=["c:\\dir\\"]))
    assert not hit(d, fields(v=["c:\\dir"]))


# ================================================================================================ LBT-04 modifiers
def test_modifier_contains_startswith_endswith():
    f = fields(v=["Hello World"])
    assert hit(det({"V|contains": "lo wo"}), f)
    assert not hit(det({"V|contains": "xyz"}), f)
    assert hit(det({"V|startswith": "hello"}), f)
    assert not hit(det({"V|startswith": "world"}), f)
    assert hit(det({"V|endswith": "WORLD"}), f)
    assert not hit(det({"V|endswith": "hello"}), f)


def test_a_value_list_is_any_of():
    d = det({"V|contains": ["aaa", "bbb"]})
    assert hit(d, fields(v=["xxbbbxx"]))
    assert hit(d, fields(v=["aaa"]))
    assert not hit(d, fields(v=["ccc"]))


def test_modifier_all_needs_every_value():
    d = det({"V|contains|all": ["aaa", "bbb"]})
    assert hit(d, fields(v=["aaa bbb"]))
    assert not hit(d, fields(v=["aaa only"]))
    assert not hit(d, fields(v=["bbb only"]))


def test_one_map_is_an_and_over_its_items_and_a_list_of_maps_is_an_or():
    anded = det({"A": "1", "B": "2"})
    assert hit(anded, fields(a=["1"], b=["2"])) and not hit(anded, fields(a=["1"], b=["9"]))
    ored = det([{"A": "1"}, {"B": "2"}])
    assert hit(ored, fields(a=["1"]))
    assert hit(ored, fields(b=["2"]))
    assert not hit(ored, fields(a=["9"], b=["9"]))


# ================================================================================================ LBT-04 conditions
def cond(text: str, **sels) -> mt.Detection:
    block = {"condition": text}
    block.update(sels)
    return mt.compile_detection(block)


SELS = {"s_a": {"A": "1"}, "s_b": {"B": "1"}, "s_c": {"C": "1"}}


def truth(text: str, **vals: bool) -> bool:
    """Evaluate a condition over s_a / s_b / s_c with the given truth values (a=True means A matches)."""
    d = cond(text, **SELS)
    f = {k.upper(): ["1" if v else "0"] for k, v in vals.items()}
    return hit(d, mt.event_fields(f))


@pytest.mark.parametrize("a,b,expected", [(True, True, True), (True, False, False), (False, True, False),
                                          (False, False, False)])
def test_condition_and(a, b, expected):
    assert truth("s_a and s_b", a=a, b=b, c=False) is expected


@pytest.mark.parametrize("a,b,expected", [(True, True, True), (True, False, True), (False, True, True),
                                          (False, False, False)])
def test_condition_or(a, b, expected):
    assert truth("s_a or s_b", a=a, b=b, c=False) is expected


def test_condition_not():
    assert truth("not s_a", a=False, b=False, c=False) is True
    assert truth("not s_a", a=True, b=False, c=False) is False
    assert truth("s_a and not s_b", a=True, b=False, c=False) is True
    assert truth("s_a and not s_b", a=True, b=True, c=False) is False


def test_condition_parentheses_and_precedence():
    # not binds tighter than and, and tighter than or
    assert truth("s_a or s_b and s_c", a=True, b=False, c=False) is True        # a or (b and c)
    assert truth("(s_a or s_b) and s_c", a=True, b=False, c=False) is False
    assert truth("(s_a or s_b) and s_c", a=True, b=False, c=True) is True
    assert truth("not (s_a or s_b)", a=False, b=False, c=False) is True
    assert truth("not (s_a or s_b)", a=False, b=True, c=False) is False
    assert truth("not s_a and s_b", a=False, b=True, c=False) is True


def test_condition_one_of_pattern_and_them():
    assert truth("1 of s_*", a=False, b=False, c=True) is True
    assert truth("1 of s_*", a=False, b=False, c=False) is False
    assert truth("1 of them", a=False, b=True, c=False) is True
    assert truth("1 of them", a=False, b=False, c=False) is False


def test_condition_all_of_pattern_and_them():
    assert truth("all of s_*", a=True, b=True, c=True) is True
    assert truth("all of s_*", a=True, b=True, c=False) is False
    assert truth("all of them", a=True, b=True, c=True) is True
    assert truth("all of them", a=True, b=False, c=True) is False


def test_condition_of_pattern_inside_a_larger_expression():
    d = mt.compile_detection({"selection": {"A": "1"}, "filter_x": {"B": "1"}, "filter_y": {"C": "1"},
                              "condition": "selection and not 1 of filter_*"})
    assert hit(d, mt.event_fields({"A": ["1"]}))
    assert not hit(d, mt.event_fields({"A": ["1"], "B": ["1"]}))
    assert not hit(d, mt.event_fields({"A": ["1"], "C": ["1"]}))


def test_condition_keywords_are_case_sensitive_lower_case_words():
    """The subset knows lower-case `and` / `or` / `not`; an unknown token is refused, not guessed."""
    with pytest.raises(LabelError):
        cond("s_a AND s_b", **SELS)


# ================================================================================================ LBT-04 refusals
@pytest.mark.parametrize("key", ["V|re", "V|base64", "V|base64offset|contains", "V|windash", "V|cidr", "V|lt",
                                 "V|gte", "V|fieldref", "V|exists", "V|contains|contains", "V|all|all",
                                 "V|utf16le|base64"])
def test_unsupported_or_repeated_modifier_is_refused(key):
    with pytest.raises(LabelError):
        det({key: "x"})


@pytest.mark.parametrize("name", ["a.b", "Foo_Bar", "1Field", "a b", "", "Foo-Bar"])
def test_field_name_outside_the_mapping_is_refused(name):
    with pytest.raises(LabelError):
        det({name: "x"})


@pytest.mark.parametrize("value", [True, False, None, 1.5, {"a": "b"}])
def test_rule_value_outside_the_subset_is_refused(value):
    """YAML 1.1 reads yes / no / null as booleans / None (decision 057): refused, never guessed."""
    with pytest.raises(LabelError):
        det({"V": value})


def test_empty_value_list_is_refused():
    with pytest.raises(LabelError):
        det({"V": []})


@pytest.mark.parametrize("text", ["selection | count() > 1", "selection | near other", "2 of s_*", "selection and",
                                  "( selection", "selection )", "", "not", "1 of nomatch_*", "selection or unknown",
                                  "selection selection", "count(selection) > 1", "all of"])
def test_condition_outside_the_subset_is_refused(text):
    with pytest.raises(LabelError):
        mt.compile_detection({"selection": {"A": "1"}, "condition": text})


def test_condition_as_a_list_or_missing_is_refused():
    with pytest.raises(LabelError):
        mt.compile_detection({"selection": {"A": "1"}, "condition": ["selection", "selection"]})
    with pytest.raises(LabelError):
        mt.compile_detection({"selection": {"A": "1"}})


def test_timeframe_and_empty_detection_are_refused():
    with pytest.raises(LabelError):
        mt.compile_detection({"selection": {"A": "1"}, "timeframe": "5m", "condition": "selection"})
    with pytest.raises(LabelError):
        mt.compile_detection({"condition": "selection"})


def test_keyword_list_selection_is_refused():
    with pytest.raises(LabelError):
        det(["keyword one", "keyword two"])


# ---------------------------------------------------------------- rule-file level (parse_rule)
ENTRY = RuleEntry("SR-99", "SR-99_x.yml", "own", "T1570")


def rule_text(*, level: str = "low", logsource: str = "product: windows\n    service: security",
              detection: str = "selection:\n        EventID: 4697\n    condition: selection",
              extra: str = "") -> str:
    return (f"title: T\nid: 11111111-1111-1111-1111-111111111111\nlogsource:\n    {logsource}\n"
            f"detection:\n    {detection}\nlevel: {level}\ntags:\n    - attack.execution\n    - attack.t1570\n{extra}")


def test_a_minimal_valid_own_rule_parses():
    r = parse_rule(rule_text(), ENTRY)
    assert r.rule_id == "SR-99" and r.level == "low" and r.level_value == 1


def test_unsupported_modifier_refuses_the_rule_file():
    with pytest.raises(LabelError):
        parse_rule(rule_text(detection="selection:\n        Foo|re: 'x'\n    condition: selection"), ENTRY)


def test_unsupported_field_refuses_the_rule_file():
    with pytest.raises(LabelError):
        parse_rule(rule_text(detection="selection:\n        Foo.Bar: 'x'\n    condition: selection"), ENTRY)


@pytest.mark.parametrize("logsource", ["product: linux\n    service: auth",
                                       "product: windows\n    category: registry_event",
                                       "product: windows\n    service: application",
                                       "product: windows",
                                       "product: windows\n    category: process_creation\n    service: security",
                                       "product: windows\n    service: security\n    extra: x"])
def test_unsupported_logsource_refuses_the_rule_file(logsource):
    with pytest.raises(LabelError):
        parse_rule(rule_text(logsource=logsource), ENTRY)


@pytest.mark.parametrize("category,channels", [("process_access", {("Sysmon", 10)}),
                                               ("process_creation", {("Sysmon", 1), ("Security", 4688)}),
                                               ("network_connection", {("Sysmon", 3)}),
                                               ("ps_module", {("PowerShell", 4103)})])
def test_supported_logsource_categories_apply_to_the_spec_events(category, channels):
    r = parse_rule(rule_text(logsource=f"product: windows\n    category: {category}"), ENTRY)
    for ch, eid in [("Sysmon", 1), ("Sysmon", 3), ("Sysmon", 10), ("Security", 4688), ("PowerShell", 4103),
                    ("Security", 4624), ("System", 7045)]:
        assert r.logsource.applies(ch, eid) is ((ch, eid) in channels), (category, ch, eid)


def test_service_logsources_cover_the_whole_channel():
    sec = parse_rule(rule_text(), ENTRY)
    sysm = parse_rule(rule_text(logsource="product: windows\n    service: system"), ENTRY)
    assert sec.logsource.applies("Security", 4697) and sec.logsource.applies("Security", 1)
    assert not sec.logsource.applies("System", 4697)
    assert sysm.logsource.applies("System", 7045) and not sysm.logsource.applies("Security", 7045)


@pytest.mark.parametrize("level", ["urgent", "none", "Low2", "5", "informational2"])
def test_level_outside_the_sigma_set_refuses_the_rule_file(level):
    with pytest.raises(LabelError):
        parse_rule(rule_text(level=level), ENTRY)


@pytest.mark.parametrize("level,value", [("informational", 0), ("low", 1), ("medium", 2), ("high", 3), ("critical", 4)])
def test_level_value_map_is_locked(level, value):
    """Correction G: informational 0 ... critical 4. An own rule must be `low` (LB-07), so a SigmaHQ-entry is used."""
    sig = RuleEntry("SR-98", "SR-98_x.yml", "sigmahq", "T1570", sigma_id="11111111-1111-1111-1111-111111111111")
    assert parse_rule(rule_text(level=level), sig).level_value == value


def test_an_own_rule_above_low_is_refused_lb07():
    with pytest.raises(LabelError):
        parse_rule(rule_text(level="medium"), ENTRY)


def test_correlation_and_filter_meta_rules_are_refused_lb02():
    with pytest.raises(LabelError):
        parse_rule(rule_text(extra="correlation:\n    type: event_count\n"), ENTRY)


def test_malformed_yaml_is_refused():
    with pytest.raises(LabelError):
        parse_rule("title: [unclosed\n", ENTRY)


def test_matching_is_deterministic_for_one_event_json():
    """The same field_values_json parsed twice gives the same fields (no hidden state)."""
    raw = json.dumps({"A": ["1"], "B": ["x", "y"]})
    assert mt.event_fields(json.loads(raw)) == mt.event_fields(json.loads(raw))
