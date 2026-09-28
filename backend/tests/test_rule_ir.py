"""Rule IR: validation, deterministic Suricata compilation, revision handling."""
import pytest

from app.domain.rule_ir import (
    LOCAL_SID_MAX,
    LOCAL_SID_MIN,
    RuleContent,
    RuleHeader,
    RuleIR,
    RuleMeta,
    compile_suricata,
    next_revision,
    parse_rule_ir,
    validate_rule_ir,
)

IR_DOCUMENT = {
    "header": {
        "action": "alert",
        "protocol": "tcp",
        "source": "$HOME_NET",
        "sourcePort": "any",
        "direction": "->",
        "destination": "$EXTERNAL_NET",
        "destinationPort": "[80, 443]",
    },
    "contents": [{"pattern": "GET /admin", "nocase": True, "modifiers": ["http_uri"]}],
    "flow": "to_server,established",
    "meta": {
        "sid": 1_000_123,
        "rev": 1,
        "msg": "疑似管理接口探测",
        "classtype": "attempted-recon",
        "priority": 2,
        "references": ["cve,CVE-2024-1234"],
        "mitreTechniques": ["T1046"],
        "metadata": {"created_at": "2026-09-09"},
    },
}


def test_valid_ir_compiles_to_deterministic_suricata_text():
    ir = parse_rule_ir(IR_DOCUMENT)
    first = compile_suricata(ir)
    second = compile_suricata(parse_rule_ir(IR_DOCUMENT))
    assert first == second
    assert first.startswith("alert tcp $HOME_NET any -> $EXTERNAL_NET [80, 443] (")
    assert 'msg:"疑似管理接口探测"' in first
    assert "flow:to_server,established" in first
    assert 'content:"GET /admin"' in first
    assert "nocase" in first and "http_uri" in first
    assert "sid:1000123" in first
    assert "rev:1" in first
    assert "classtype:attempted-recon" in first
    assert "priority:2" in first
    assert "reference:cve,CVE-2024-1234" in first
    assert "mitre_technique_id T1046" in first
    assert first.endswith(";)")
    assert ir.digest() == parse_rule_ir(IR_DOCUMENT).digest()


def test_special_characters_are_escaped_not_injected():
    document = {
        **IR_DOCUMENT,
        "contents": [{"pattern": 'evil"; sid:1; msg:"pwned'}],
        "meta": {**IR_DOCUMENT["meta"], "msg": 'quote " and semicolon;'},
    }
    text = compile_suricata(parse_rule_ir(document))
    assert '\\"' in text
    assert '\\;' in text
    # The injected option syntax is escaped inside the quoted content, so it
    # cannot terminate the content and become a real rule option.
    assert "; sid:1;" not in text
    assert text.count("sid:1000123") == 1
    # The injected msg option stays inside the escaped content string.
    assert 'msg:"pwned' not in text


@pytest.mark.parametrize(
    "patch, message",
    [
        ({"meta": {"sid": 500, "rev": 1, "msg": "x"}}, "sid"),
        ({"header": {**IR_DOCUMENT["header"], "action": "exec"}}, "action"),
        ({"header": {**IR_DOCUMENT["header"], "protocol": "smtp"}}, "protocol"),
        ({"header": {**IR_DOCUMENT["header"], "destination": "not a network"}}, "destination"),
        ({"header": {**IR_DOCUMENT["header"], "destinationPort": "80-90"}}, "destinationPort"),
        ({"meta": {**IR_DOCUMENT["meta"], "rev": 0}}, "rev"),
        ({"meta": {**IR_DOCUMENT["meta"], "classtype": "made-up"}}, "classtype"),
        ({"meta": {**IR_DOCUMENT["meta"], "mitreTechniques": ["1046"]}}, "mitre"),
        ({"meta": {**IR_DOCUMENT["meta"], "references": ["nonsense"]}}, "reference"),
        ({"contents": []}, "content"),
        ({"contents": [{"pattern": "x", "modifiers": ["http_body"]}]}, "modifier"),
        ({"pcre": "/a(?{code})/"}, "pcre"),
        ({"flow": "sideways"}, "flow"),
    ],
)
def test_invalid_documents_are_rejected(patch, message):
    document = {**IR_DOCUMENT, **patch}
    if "meta" in patch and "sid" in patch["meta"]:
        document["meta"] = patch["meta"]
    with pytest.raises(ValueError) as error:
        parse_rule_ir(document)
    assert message in str(error.value)


def test_missing_structures_are_rejected():
    with pytest.raises(ValueError):
        parse_rule_ir({})
    with pytest.raises(ValueError):
        parse_rule_ir({"header": {}, "meta": {}, "contents": []})
    with pytest.raises(ValueError):
        parse_rule_ir("not a dict")  # type: ignore[arg-type]


def test_next_revision_bumps_rev_and_keeps_everything_else():
    ir = parse_rule_ir(IR_DOCUMENT)
    repaired = next_revision(ir, msg="修复后的规则")
    assert repaired.meta.rev == 2
    assert repaired.meta.sid == ir.meta.sid
    assert repaired.meta.msg == "修复后的规则"
    assert repaired.header == ir.header
    assert repaired.contents == ir.contents


def test_pcre_and_threshold_are_validated_and_compiled():
    ir = RuleIR(
        header=RuleHeader(
            action="alert",
            protocol="tcp",
            source="$HOME_NET",
            source_port="any",
            direction="->",
            destination="$EXTERNAL_NET",
            destination_port="any",
        ),
        contents=(RuleContent(pattern="SSH-", nocase=True, depth=4),),
        meta=RuleMeta(sid=LOCAL_SID_MIN, rev=3, msg="ssh banner", classtype="misc-activity"),
        flow="to_server",
        pcre="/SSH-[0-9.]+/",
        threshold="threshold: type limit, track_by_src, count 5, seconds 60",
    )
    validate_rule_ir(ir)
    text = compile_suricata(ir)
    assert 'pcre:"/SSH-[0-9.]+/"' in text
    assert "threshold: type limit, track_by_src, count 5, seconds 60" in text
    assert LOCAL_SID_MIN <= ir.meta.sid <= LOCAL_SID_MAX
