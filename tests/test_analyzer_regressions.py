"""Regression coverage for deterministic artifact analysis."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone

from forensicagent.analyzer import llm_extract
from forensicagent.analyzer.analyzer import analyze_one
from forensicagent.analyzer.rules import apply_rules
from forensicagent.analyzer.types import EvidenceRef, Finding
from forensicagent.executor.types import ExecutionResult, OutputArtifact
from forensicagent.tools.schema import CommandTemplate, SuspiciousIndicator, ToolMetadata


def _meta(*ids: str, tool_id: str = "fake") -> ToolMetadata:
    severities = {
        "amcache_credential_dump_tool": "critical",
        "clear_log_event": "critical",
        "gitleaks_aws_key": "critical",
        "gitleaks_secret": "high",
    }
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id.title(),
        category="log_analysis",
        applicable_evidence_types=["evtx_log"],
        command_templates=[
            CommandTemplate(name="test", template="test {evidence_path}", when="test")
        ],
        usage_description="test metadata",
        suspicious_indicators=[
            SuspiciousIndicator(
                id=indicator_id,
                pattern="concrete test pattern",
                severity_baseline=severities.get(indicator_id, "high"),
            )
            for indicator_id in ids
        ],
    )


def test_evtx_field_normalization_and_correlations():
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = [
        {
            "Event Id": "4625",
            "Ip Address": "8.8.8.8",
            "Time Created": (start + timedelta(seconds=index)).isoformat(),
        }
        for index in range(10)
    ]
    rows.extend(
        [
            {
                "EVENTID": 4624,
                "Logon Type": "10 - RemoteInteractive",
                "Source IP": "8.8.8.8",
                "TimeCreated": (start + timedelta(seconds=10)).isoformat(),
            },
            {"EventID": 4720, "Target User Name": "case-user"},
            {"EventID": 4732, "Member Name": "CN=case-user,CN=Users,DC=example"},
            {"EventID": 1102},
            {"EventID": 104},
            {"EventID": 4697, "Service File Name": "%TEMP%\\svc.exe"},
            {
                "EventID": 4104,
                "Script Block Text": "powershell.exe -EncodedCommand SQBFAFgA",
            },
        ]
    )
    metadata = _meta(
        "rdp_logon_external_ip",
        "rdp_logon_offhours",
        "failed_logon_burst",
        "brute_force_followed_by_success",
        "account_creation_4720",
        "clear_log_event",
        "service_install_4697",
        "powershell_encoded_command",
        tool_id="evtxecmd",
    )

    findings = apply_rules({"Results": rows}, "", metadata)
    rule_ids = {finding.rule_id for finding in findings}

    assert "rdp_logon_external_ip" in rule_ids
    assert "rdp_logon_offhours" in rule_ids
    assert "failed_logon_burst" in rule_ids
    assert "brute_force_followed_by_success" in rule_ids
    assert "account_creation_4720" in rule_ids
    assert {"clear_log_event:104", "clear_log_event:1102"} <= rule_ids
    assert "service_install_4697" in rule_ids
    assert "powershell_encoded_command" in rule_ids


def test_failed_logon_equal_timestamps_do_not_crash_or_duplicate():
    rows = [
        {"EventID": 4625, "IpAddress": "203.0.113.8", "Timestamp": "2025-01-01T00:00:00Z"}
        for _ in range(10)
    ]
    findings = apply_rules(
        {"items": rows}, "", _meta("failed_logon_burst", tool_id="evtxecmd")
    )
    assert len(findings) == 1


def test_amcache_header_benign_and_high_confidence_rows():
    rows = [
        {"Full Path": "Full Path", "Associated": "Associated"},
        {"Full Path": "C:\\Program Files\\Vendor\\app.exe", "Associated": "yes"},
        {"Full Path": "C:\\Users\\Public\\mimikatz.exe", "Associated": "false"},
        {
            "FullPath": "C:\\Users\\alice\\AppData\\Local\\Temp\\drop.exe",
            "Associated": "false",
        },
        {
            "FullPath": "C:\\Users\\alice\\tool.exe",
            "Signing Status": "unsigned",
        },
        {"FullPath": "C:\\Users\\Public\\known.exe", "Associated": "known"},
    ]
    findings = apply_rules(
        {"items": rows},
        "",
        _meta(
            "amcache_unassociated_in_temp",
            "amcache_credential_dump_tool",
            "amcache_signing_status_invalid",
            tool_id="amcacheparser",
        ),
    )
    by_rule = {finding.rule_id: finding for finding in findings}

    assert len(findings) == 3
    assert set(by_rule) == {
        "amcache_unassociated_in_temp",
        "amcache_credential_dump_tool",
        "amcache_signing_status_invalid",
    }
    assert by_rule["amcache_credential_dump_tool"].severity == "critical"


def test_mft_and_prefetch_concrete_matchers():
    mft_rows = [
        {
            "File Name": "gone.exe",
            "Parent Path": "C:\\Users\\Public",
            "In Use": "False",
            "Created0x10": "2025-01-02T00:00:00Z",
            "Created0x30": "2025-01-01T00:00:00Z",
        },
        {"File Name": "report.docx:payload.bin", "In Use": "True"},
        {"File Name": "download.zip:Zone.Identifier", "In Use": "True"},
    ]
    mft_findings = apply_rules(
        {"rows": mft_rows},
        "",
        _meta(
            "deleted_executable_in_temp",
            "timestomp_inconsistency",
            "ads_alternate_data_stream",
            tool_id="mftecmd",
        ),
    )
    assert {finding.rule_id for finding in mft_findings} == {
        "deleted_executable_in_temp",
        "timestomp_inconsistency",
        "ads_alternate_data_stream",
    }

    prefetch_rows = [
        {
            "Executable Name": "mimikatz.exe",
            "Executable Path": "C:\\Users\\Public\\mimikatz.exe",
            "Run Count": 1,
            "Last Run": "2025-01-01T00:00:00Z",
            "Files Loaded": "C:\\Temp\\lsass.dmp",
        },
        {
            "Executable Name": "random.exe",
            "Executable Path": "C:\\Temp\\random.exe",
            "Run Count": 1,
            "Last Run": "2025-01-02T00:00:00Z",
        },
    ]
    prefetch_findings = apply_rules(
        {"items": prefetch_rows},
        "",
        _meta(
            "prefetch_unusual_path",
            "prefetch_with_credential_tools",
            "prefetch_referenced_lsass_dump",
            "prefetch_run_count_one_recent",
            tool_id="pecmd",
        ),
    )
    assert {finding.rule_id for finding in prefetch_findings} == {
        "prefetch_unusual_path",
        "prefetch_with_credential_tools",
        "prefetch_referenced_lsass_dump",
        "prefetch_run_count_one_recent",
    }


def test_registry_structured_and_text_matchers():
    structured = {
        "items": [
            {
                "Key Path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\ab12cd",
                "Value Name": "ImagePath",
                "Value Data": "C:\\Users\\Public\\svc.exe",
            },
            {
                "Key Path": "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "Value Name": "Shell",
                "Value Data": "explorer.exe, C:\\Temp\\evil.exe",
            },
            {
                "Key Path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                "Value Data": "C:\\Temp\\runme.exe",
            },
        ]
    }
    findings = apply_rules(
        structured,
        "",
        _meta(
            "service_imagepath_random",
            "winlogon_shell_modified",
            "userassist_recent_exec_temp",
            tool_id="recmd",
        ),
    )
    assert {finding.rule_id for finding in findings} == {
        "service_imagepath_random",
        "winlogon_shell_modified",
        "userassist_recent_exec_temp",
    }

    raw = (
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options\\sethc.exe\n"
        "  Debugger = C:\\Temp\\cmd.exe\n"
    )
    ifeo = apply_rules(
        {}, raw, _meta("image_file_execution_debugger", tool_id="regripper")
    )
    assert len(ifeo) == 1


def test_volatility_process_and_network_matchers_exclude_private_ips():
    processes = {
        "items": [
            {"PID": 100, "PPID": 4, "ImageFileName": "evilparent.exe"},
            {
                "PID": 200,
                "PPID": 100,
                "ImageFileName": "lsass.exe",
                "Path": "C:\\Windows\\System32\\lsass.exe",
            },
            {
                "PID": 300,
                "PPID": 100,
                "Process": "drop.exe",
                "Args": "C:\\Users\\Public\\drop.exe --quiet",
            },
        ]
    }
    findings = apply_rules(
        processes,
        "",
        _meta("abnormal_parent_child", "process_in_unusual_path", tool_id="volatility3"),
    )
    assert {finding.rule_id for finding in findings} == {
        "abnormal_parent_child",
        "process_in_unusual_path",
    }

    networks = {
        "rows": [
            {
                "State": "ESTABLISHED",
                "Foreign Addr": "8.8.8.8",
                "Foreign Port": 4444,
                "Owner": "drop.exe",
            },
            {
                "State": "ESTABLISHED",
                "ForeignAddr": "10.10.10.10",
                "ForeignPort": 4444,
                "Owner": "internal.exe",
            },
            {
                "State": "ESTABLISHED",
                "ForeignAddr": "1.1.1.1",
                "ForeignPort": 443,
                "Owner": "browser.exe",
            },
        ]
    }
    network_findings = apply_rules(
        networks,
        "",
        _meta("netscan_to_known_bad_or_rare_ip", tool_id="volatility3"),
    )
    assert len(network_findings) == 1
    assert "8.8.8.8:4444" in network_findings[0].description


def test_volatility_malfind_csv_fields_and_raw_fallback():
    rows = {
        "items": [
            {
                "PID": 444,
                "Process": "suspect.exe",
                "Hex Dump": "4d 5a 90 00 03 00 00 00",
                "Vad Protection": "PAGE_EXECUTE_READWRITE",
                "Private Memory": "True",
                "Tag": "VadS",
                "File Output": "",
            },
            {
                "PID": 445,
                "Process": "mapped.exe",
                "Hexdump": "4d 5a 90 00",
                "Protection": "PAGE_READWRITE",
                "PrivateMemory": "False",
                "Tag": "Vad",
                "FileOutput": "C:\\Windows\\System32\\mapped.dll",
            },
        ]
    }
    findings = apply_rules(
        rows,
        "",
        _meta("malfind_pe_in_unbacked_region", tool_id="volatility3"),
    )
    assert len(findings) == 1
    assert "PID 444" in findings[0].description

    raw = "PID 444 suspect.exe\nProtection: PAGE_EXECUTE_READWRITE RX MZ\nNo mapped path\n"
    raw_findings = apply_rules(
        {}, raw, _meta("malfind_pe_in_unbacked_region", tool_id="volatility3")
    )
    assert len(raw_findings) == 1


def test_scanner_parsers_own_severity_and_do_not_duplicate_or_leak_secret():
    bandit = {
        "results": [
            {
                "test_id": "B324",
                "issue_text": "weak hash",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "app.py",
                "line_number": 7,
                "code": "hashlib.md5(data)",
            }
        ]
    }
    bandit_findings = apply_rules(
        bandit, "", _meta("bandit_issue", "bandit_high", tool_id="bandit")
    )
    assert len(bandit_findings) == 1
    assert bandit_findings[0].severity == "high"
    assert bandit_findings[0].rule_id == "bandit:B324"

    semgrep = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app.py",
                "start": {"line": 12},
                "extra": {"severity": "ERROR", "message": "eval", "lines": "eval(user)"},
            }
        ]
    }
    semgrep_findings = apply_rules(
        semgrep, "", _meta("semgrep_issue", "semgrep_high", tool_id="semgrep")
    )
    assert len(semgrep_findings) == 1
    assert semgrep_findings[0].severity == "high"

    secret = "AKIAABCDEFGHIJKLMNOP"
    gitleaks = [
        {
            "RuleID": "aws-access-token",
            "Description": f"AWS key {secret}",
            "File": "src/settings.py",
            "StartLine": 3,
            "Secret": secret,
            "Match": f"AWS_KEY={secret}",
        },
        {
            "RuleID": "generic-api-key",
            "Description": "example",
            "File": ".env.example",
            "StartLine": 1,
            "Secret": "replace_with_your_api_key",
        },
    ]
    leak_findings = apply_rules(
        gitleaks,
        "",
        _meta("gitleaks_secret", "gitleaks_aws_key", tool_id="gitleaks"),
    )
    assert len(leak_findings) == 1
    assert leak_findings[0].severity == "critical"
    assert secret not in leak_findings[0].description
    assert secret not in leak_findings[0].title
    assert secret not in leak_findings[0].evidence_ref.raw_excerpt
    assert "[REDACTED]" in leak_findings[0].evidence_ref.raw_excerpt


def test_fingerprint_is_deterministic_and_confidence_is_clamped():
    kwargs = dict(
        severity="high",
        title="Same",
        rule_id="rule:same",
        evidence_ref=EvidenceRef(
            source_file="CASE/FILE.CSV",
            event_id=42,
            timestamp="2025-01-01T00:00:00Z",
            raw_excerpt="same   evidence",
        ),
    )
    first = Finding(**kwargs, confidence=2)
    second = Finding(**kwargs, confidence=1)
    assert first.fingerprint == second.fingerprint
    assert first.finding_id != second.finding_id
    assert first.confidence == 1.0


def test_same_second_distinct_events_are_not_deduplicated():
    result = ExecutionResult(
        tool_id="evtxecmd",
        status="success",
        target_evidence="Security.evtx",
        parsed_output={
            "items": [
                {
                    "EventID": 1102,
                    "Timestamp": "2025-01-01T00:00:00Z",
                    "SubjectUserName": "alice",
                },
                {
                    "EventID": 1102,
                    "Timestamp": "2025-01-01T00:00:00Z",
                    "SubjectUserName": "bob",
                },
            ]
        },
    )
    analysis = analyze_one(
        result,
        _meta("clear_log_event", tool_id="evtxecmd"),
        use_llm=False,
    )
    assert len(analysis.findings) == 2
    assert len({finding.fingerprint for finding in analysis.findings}) == 2


def test_generated_csv_tail_and_partial_failure_are_analyzed(tmp_path):
    csv_path = tmp_path / "mft.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["File Name", "Parent Path", "In Use"])
        writer.writeheader()
        for index in range(5_020):
            writer.writerow(
                {
                    "File Name": f"benign-{index}.txt",
                    "Parent Path": "C:\\Documents",
                    "In Use": "True",
                }
            )
        writer.writerow(
            {
                "File Name": "tail.exe",
                "Parent Path": "C:\\Users\\Public",
                "In Use": "False",
            }
        )
    stdout_path = tmp_path / "stdout.log"
    stdout_path.write_text("progress: generated CSV complete", encoding="utf-8")
    result = ExecutionResult(
        tool_id="mftecmd",
        target_evidence="C:\\case\\$MFT",
        status="output_missing",
        artifacts=[
            OutputArtifact(
                path=str(stdout_path), role="stdout", format="text", size_bytes=stdout_path.stat().st_size
            ),
            OutputArtifact(
                path=str(csv_path), role="generated", format="csv", size_bytes=csv_path.stat().st_size
            ),
        ],
        warnings=["expected output name differed"],
    )

    analysis = analyze_one(
        result,
        _meta("deleted_executable_in_temp", tool_id="mftecmd"),
        use_llm=False,
    )

    assert len(analysis.findings) == 1
    assert analysis.findings[0].evidence_ref.source_file.endswith("tail.exe")
    assert "deterministic=1" in analysis.summary
    assert "execution_status=output_missing" in analysis.summary
    assert "executor_warnings=1" in analysis.summary


def test_case_c_text_stream_reaches_tail(tmp_path):
    output = tmp_path / "regripper.txt"
    filler = "normal registry output\n" * 210_000
    output.write_text(
        filler
        + "Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        + "  tail = %Temp%\\tail.exe\n",
        encoding="utf-8",
    )
    result = ExecutionResult(
        tool_id="regripper",
        status="success",
        target_evidence="NTUSER.DAT",
        artifacts=[
            OutputArtifact(
                path=str(output), role="stdout", format="text", size_bytes=output.stat().st_size
            )
        ],
    )
    analysis = analyze_one(
        result,
        _meta("run_key_unusual_binary", tool_id="regripper"),
        use_llm=False,
    )
    assert analysis.case_used == "C"
    assert len(analysis.findings) == 1


def test_dict_shaped_execution_and_artifact_are_compatible(tmp_path):
    output = tmp_path / "registry.txt"
    output.write_text(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        "dict-result = %Temp%\\dict.exe\n",
        encoding="utf-8",
    )
    result = {
        "tool_id": "regripper",
        "status": "failed",
        "target_evidence": "NTUSER.DAT",
        "artifacts": [
            {
                "path": str(output),
                "role": "stdout",
                "format": "text",
                "size_bytes": output.stat().st_size,
            }
        ],
        "warnings": ["partial"],
    }
    analysis = analyze_one(  # type: ignore[arg-type]
        result,
        _meta("run_key_unusual_binary", tool_id="regripper"),
        use_llm=False,
    )
    assert len(analysis.findings) == 1
    assert "execution_status=failed" in analysis.summary


class _GroundedClient:
    def __init__(self):
        self.messages = None
        self.kwargs = None

    def json_chat(self, messages, **kwargs):
        self.messages = messages
        self.kwargs = kwargs
        return {
            "findings": [
                {
                    "severity": "high",
                    "category": "persistence",
                    "title": "Grounded model note",
                    "description": "Model commentary on deterministic evidence.",
                    "raw_excerpt": "evil = %Temp%\\bad.exe",
                    "suggested_followup": "Inspect it.",
                    "confidence": 0.9,
                }
            ],
            "summary": "model context",
        }


def test_case_b_llm_receives_only_grounded_rule_excerpt_and_counts_survive(tmp_path):
    output = tmp_path / "registry.txt"
    output.write_text(
        "BENIGN-LARGE-MARKER\n" * 6_000
        + "Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        + "evil = %Temp%\\bad.exe\n",
        encoding="utf-8",
    )
    client = _GroundedClient()
    result = ExecutionResult(
        tool_id="regripper",
        status="success",
        target_evidence="NTUSER.DAT",
        artifacts=[
            OutputArtifact(
                path=str(output), role="stdout", format="text", size_bytes=output.stat().st_size
            )
        ],
    )
    analysis = analyze_one(
        result,
        _meta("run_key_unusual_binary", tool_id="regripper"),
        client=client,
        use_llm=True,
        use_rag=False,
    )
    prompt = client.messages[-1].content

    assert analysis.case_used == "B"
    assert "BENIGN-LARGE-MARKER" not in prompt
    assert "evil = %Temp%\\bad.exe" in prompt
    assert client.kwargs["format_schema"]["type"] == "object"
    assert len(analysis.findings) == 2
    assert "deterministic=1" in analysis.summary
    assert "llm_note=model context" in analysis.summary
    assert next(f for f in analysis.findings if f.source == "llm").confidence == 0.6


class _UngroundedClient:
    def json_chat(self, messages, **kwargs):
        return {
            "findings": [
                {
                    "severity": "critical",
                    "category": "anomaly",
                    "title": "Invented",
                    "description": "Invented evidence",
                    "raw_excerpt": "this text never appeared",
                    "suggested_followup": "None",
                    "confidence": 1,
                }
            ],
            "summary": "claimed compromise",
        }


def test_llm_ungrounded_excerpt_is_dropped():
    findings, summary, invoked, failed = llm_extract.extract(
        _meta(tool_id="fake"), "actual evidence only", client=_UngroundedClient()
    )
    assert findings == []
    assert summary == "claimed compromise"
    assert invoked is True
    assert failed is False


class _LegacyClient:
    def json_chat(self, messages, retry):
        return {"findings": [], "summary": "legacy ok"}


def test_llm_schema_falls_back_for_legacy_fake_clients():
    findings, summary, invoked, failed = llm_extract.extract(
        _meta(tool_id="fake"), "actual evidence only", client=_LegacyClient()
    )
    assert findings == []
    assert summary == "legacy ok"
    assert invoked is True
    assert failed is False
