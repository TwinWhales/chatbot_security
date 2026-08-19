"""Regression coverage for deterministic artifact analysis."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone

from forensicagent.analyzer import llm_extract
from forensicagent.analyzer.analyzer import CASE_A_MAX, CASE_B_MAX, analyze_one
from forensicagent.analyzer.rules import apply_rules, supported_indicator_ids
from forensicagent.analyzer.types import MAX_RETAINED_FINDINGS, EvidenceRef, Finding
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
            {
                "EventID": 4732,
                "Member Name": "CN=case-user,CN=Users,DC=example",
                "TargetSid": "S-1-5-32-544",
                "TargetUserName": "Administrators",
            },
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


def test_failed_logon_without_timestamps_does_not_claim_a_time_window():
    rows = [
        {"EventID": 4625, "IpAddress": "203.0.113.8"}
        for _ in range(10)
    ]
    finding = apply_rules(
        {"items": rows}, "", _meta("failed_logon_burst", tool_id="evtxecmd")
    )[0]

    assert "time window unavailable" in finding.description
    assert "within five minutes" not in finding.description


def test_rdp_offhours_uses_configured_local_offset(monkeypatch):
    from forensicagent.analyzer import rules

    monkeypatch.setattr(rules.settings, "RDP_UTC_OFFSET_MINUTES", 9 * 60)
    monkeypatch.setattr(rules.settings, "RDP_BUSINESS_START_HOUR", 7)
    monkeypatch.setattr(rules.settings, "RDP_BUSINESS_END_HOUR", 20)
    metadata = _meta("rdp_logon_offhours", tool_id="chainsaw")

    business_hours = apply_rules(
        {"items": [{"EventID": 4624, "LogonType": 10, "Timestamp": "2025-01-01T00:00:00Z"}]},
        "",
        metadata,
    )
    off_hours = apply_rules(
        {"items": [{"EventID": 4624, "LogonType": 10, "Timestamp": "2025-01-01T12:00:00Z"}]},
        "",
        metadata,
    )

    assert business_hours == []
    assert len(off_hours) == 1
    assert "+09:00" in off_hours[0].description


def test_service_install_supports_system_7045_image_path():
    rows = [
        {
            "EventID": 7045,
            "ServiceName": "case-service",
            "ImagePath": "C:\\Users\\Public\\svc.exe",
        },
        {
            "EventID": 7045,
            "ServiceName": "normal-service",
            "ImagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        },
    ]

    findings = apply_rules(
        {"items": rows}, "", _meta("service_install_4697", tool_id="chainsaw")
    )

    assert len(findings) == 1
    assert findings[0].evidence_ref.event_id == 7045
    assert "svc.exe" in findings[0].description


def test_new_account_requires_privileged_group_and_bounded_time():
    rows = [
        {
            "EventID": 4720,
            "TargetUserName": "ordinary-user",
            "Timestamp": "2025-01-01T00:00:00Z",
        },
        {
            "EventID": 4732,
            "MemberName": "ordinary-user",
            "TargetUserName": "Users",
            "TargetSid": "S-1-5-32-545",
            "Timestamp": "2025-01-01T00:01:00Z",
        },
        {
            "EventID": 4720,
            "TargetUserName": "stale-user",
            "Timestamp": "2025-01-01T00:00:00Z",
        },
        {
            "EventID": 4732,
            "MemberName": "stale-user",
            "TargetUserName": "Administrators",
            "TargetSid": "S-1-5-32-544",
            "Timestamp": "2025-01-01T02:00:00Z",
        },
        {
            "EventID": 4720,
            "TargetUserName": "fresh-user",
            "Timestamp": "2025-01-01T00:00:00Z",
        },
        {
            "EventID": 4732,
            "MemberName": "fresh-user",
            "TargetUserName": "Administrators",
            "Timestamp": "2025-01-01T00:30:00Z",
        },
        {"EventID": 4720, "TargetUserName": "untimed-user"},
        {
            "EventID": 4732,
            "MemberName": "untimed-user",
            "TargetSid": "S-1-5-32-551",
        },
    ]

    findings = apply_rules(
        {"items": rows}, "", _meta("account_creation_4720", tool_id="evtxecmd")
    )

    assert len(findings) == 2
    by_account = {
        finding.evidence_ref.raw_excerpt.split(";")[0]: finding
        for finding in findings
    }
    assert by_account["account=fresh-user"].confidence == 0.97
    assert by_account["account=untimed-user"].confidence == 0.72


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
            tool_id="pecmd",
        ),
    )
    assert {finding.rule_id for finding in prefetch_findings} == {
        "prefetch_unusual_path",
        "prefetch_with_credential_tools",
        "prefetch_referenced_lsass_dump",
    }


def test_prefetch_uses_only_the_executable_for_path_and_tool_rules():
    rows = [
        {
            "ExecutableName": "explorer.exe",
            "ExecutablePath": "C:\\Windows\\explorer.exe",
            "FilesLoaded": "C:\\Temp\\mimikatz-notes.txt",
        },
        {
            "ExecutableName": "wmic.exe",
            "ExecutablePath": "C:\\Windows\\System32\\wbem\\wmic.exe",
        },
        {
            "ExecutableName": "notmimikatzhelper.exe",
            "ExecutablePath": "C:\\Tools\\notmimikatzhelper.exe",
        },
        {
            "ExecutableName": "nanodump.exe",
            "ExecutablePath": "C:\\Tools\\nanodump.exe",
        },
    ]

    findings = apply_rules(
        {"items": rows},
        "",
        _meta(
            "prefetch_unusual_path",
            "prefetch_with_credential_tools",
            tool_id="pecmd",
        ),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "prefetch_with_credential_tools"
    assert "nanodump.exe" in findings[0].description


def test_prefetch_single_file_cannot_claim_relative_recency():
    row = {
        "ExecutableName": "drop.exe",
        "ExecutablePath": "C:\\Temp\\drop.exe",
        "RunCount": 1,
        "LastRun": "2010-01-01T00:00:00Z",
    }

    assert "prefetch_run_count_one_recent" not in supported_indicator_ids()
    assert apply_rules(
        {"items": [row]},
        "",
        _meta("prefetch_run_count_one_recent", tool_id="pecmd"),
    ) == []


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
            "userassist_temp_execution",
            tool_id="recmd",
        ),
    )
    assert {finding.rule_id for finding in findings} == {
        "service_imagepath_random",
        "winlogon_shell_modified",
        "userassist_temp_execution",
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


def test_regripper_userassist_raw_temp_execution_needs_no_signature_field():
    raw = (
        "UserAssist\n"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\n"
        "LastWrite Time 2025-01-01T00:00:00Z\n\n"
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\n"
        "2025-01-01T01:00:00Z\n"
        "  C:\\Users\\alice\\Downloads\\drop.exe (1)\n"
    )

    findings = apply_rules(
        {}, raw, _meta("userassist_temp_execution", tool_id="regripper")
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "userassist_temp_execution"
    assert findings[0].confidence == 0.82
    assert "drop.exe" in findings[0].description


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
    credential_literal = "super-secret-password-value"
    bandit = {
        "results": [
            {
                "test_id": "B324",
                "issue_text": f"hardcoded password is {credential_literal}",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "app.py",
                "line_number": 7,
                "code": f"password = '{credential_literal}'",
            }
        ]
    }
    bandit_findings = apply_rules(
        bandit, "", _meta("bandit_issue", "bandit_high", tool_id="bandit")
    )
    assert len(bandit_findings) == 1
    assert bandit_findings[0].severity == "high"
    assert bandit_findings[0].rule_id == "bandit:B324"
    assert credential_literal not in str(bandit_findings[0].to_dict())

    semgrep = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app.py",
                "start": {"line": 12},
                "extra": {
                    "severity": "ERROR",
                    "message": f"hardcoded token is {credential_literal}",
                    "lines": f"token = '{credential_literal}'",
                    "fix": f"replace {credential_literal}",
                },
            }
        ]
    }
    semgrep_findings = apply_rules(
        semgrep, "", _meta("semgrep_issue", "semgrep_high", tool_id="semgrep")
    )
    assert len(semgrep_findings) == 1
    assert semgrep_findings[0].severity == "high"
    assert credential_literal not in str(semgrep_findings[0].to_dict())

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


def test_real_secret_in_example_file_is_not_suppressed():
    secret = "AKIAABCDEFGHIJKLMNOP"
    findings = apply_rules(
        [
            {
                "RuleID": "aws-access-token",
                "Description": "AWS access token",
                "File": ".env.example",
                "StartLine": 4,
                "Secret": secret,
                "Match": f"AWS_ACCESS_KEY_ID={secret}",
            }
        ],
        "",
        _meta("gitleaks_secret", tool_id="gitleaks"),
    )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert secret not in findings[0].evidence_ref.raw_excerpt


def test_bandit_and_gitleaks_csv_reports_are_analyzed(tmp_path):
    bandit_report = tmp_path / "bandit.csv"
    with bandit_report.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "filename",
                "test_name",
                "test_id",
                "issue_severity",
                "issue_confidence",
                "issue_cwe",
                "issue_text",
                "line_number",
                "col_offset",
                "end_col_offset",
                "line_range",
                "more_info",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "filename": "app.py",
                "test_id": "B324",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "weak hash",
                "line_number": 7,
            }
        )
    bandit = analyze_one(
        ExecutionResult(
            tool_id="bandit",
            status="success",
            artifacts=[
                OutputArtifact(
                    path=str(bandit_report),
                    role="generated",
                    format="csv",
                    size_bytes=bandit_report.stat().st_size,
                )
            ],
        ),
        _meta("bandit_issue", tool_id="bandit"),
        use_llm=False,
    )

    secret = "AKIAABCDEFGHIJKLMNOP"
    gitleaks_report = tmp_path / "gitleaks.csv"
    with gitleaks_report.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "RuleID",
                "Commit",
                "File",
                "SymlinkFile",
                "Secret",
                "Match",
                "StartLine",
                "EndLine",
                "StartColumn",
                "EndColumn",
                "Author",
                "Message",
                "Date",
                "Email",
                "Fingerprint",
                "Tags",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "RuleID": "aws-access-token",
                "File": "settings.py",
                "Secret": secret,
                "Match": f"AWS_ACCESS_KEY_ID={secret}",
                "StartLine": 3,
            }
        )
    gitleaks = analyze_one(
        ExecutionResult(
            tool_id="gitleaks",
            status="success",
            artifacts=[
                OutputArtifact(
                    path=str(gitleaks_report),
                    role="generated",
                    format="csv",
                    size_bytes=gitleaks_report.stat().st_size,
                )
            ],
        ),
        _meta("gitleaks_secret", tool_id="gitleaks"),
        use_llm=False,
    )

    assert [(finding.rule_id, finding.severity) for finding in bandit.findings] == [
        ("bandit:B324", "high")
    ]
    assert [(finding.rule_id, finding.severity) for finding in gitleaks.findings] == [
        ("gitleaks:aws-access-token", "critical")
    ]
    assert secret not in gitleaks.findings[0].evidence_ref.raw_excerpt


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


def test_large_json_is_retained_without_unbounded_parse(tmp_path):
    output = tmp_path / "large.json"
    output.write_text(
        '{"items":[{"EventID":4624,"padding":"'
        + ("x" * CASE_B_MAX)
        + '"}]}',
        encoding="utf-8",
    )
    result = ExecutionResult(
        tool_id="chainsaw",
        status="success",
        target_evidence="Security.evtx",
        artifacts=[
            OutputArtifact(
                path=str(output),
                role="stdout",
                format="json",
                size_bytes=1,
            )
        ],
    )

    analysis = analyze_one(result, _meta(tool_id="chainsaw"), use_llm=False)

    assert analysis.case_used == "C"
    assert analysis.findings == []
    assert "coverage_truncated=true" in analysis.summary
    assert "raw artifact retained" in analysis.summary
    assert output.is_file()


def test_oversized_ndjson_record_is_skipped_but_tail_is_analyzed(tmp_path):
    output = tmp_path / "events.ndjson"
    output.write_text(
        '{"EventID":4624,"padding":"'
        + ("x" * CASE_A_MAX)
        + '"}\n{"EventID":1102}\n',
        encoding="utf-8",
    )
    result = ExecutionResult(
        tool_id="chainsaw",
        status="success",
        target_evidence="Security.evtx",
        artifacts=[
            OutputArtifact(
                path=str(output),
                role="stdout",
                format="json",
                size_bytes=1,
            )
        ],
    )

    analysis = analyze_one(
        result,
        _meta("clear_log_event", tool_id="chainsaw"),
        use_llm=False,
    )

    assert [finding.rule_id for finding in analysis.findings] == [
        "clear_log_event:1102"
    ]
    assert "coverage_truncated=true" in analysis.summary
    assert "oversized records were skipped" in analysis.summary


def _service_install_result(count: int) -> ExecutionResult:
    return ExecutionResult(
        tool_id="evtxecmd",
        status="success",
        target_evidence="Security.evtx",
        parsed_output={
            "items": [
                {
                    "EventID": 4697,
                    "ServiceFileName": f"%TEMP%\\service-{index}.exe",
                }
                for index in range(count)
            ]
        },
    )


def test_exact_finding_limit_does_not_claim_truncation():
    analysis = analyze_one(
        _service_install_result(MAX_RETAINED_FINDINGS),
        _meta("service_install_4697", tool_id="evtxecmd"),
        use_llm=False,
    )

    assert len(analysis.findings) == MAX_RETAINED_FINDINGS
    assert analysis.finding_limit_reached is False
    assert "finding_limit_reached=true" not in analysis.summary


def test_one_over_finding_limit_claims_truncation():
    analysis = analyze_one(
        _service_install_result(MAX_RETAINED_FINDINGS + 1),
        _meta("service_install_4697", tool_id="evtxecmd"),
        use_llm=False,
    )

    assert len(analysis.findings) == MAX_RETAINED_FINDINGS
    assert analysis.finding_limit_reached is True
    assert "finding_limit_reached=true" in analysis.summary


def test_finding_limit_keeps_critical_tail_after_noisy_batch(tmp_path):
    output = tmp_path / "events.csv"
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["EventID", "ServiceFileName"],
        )
        writer.writeheader()
        for index in range(600):
            writer.writerow(
                {
                    "EventID": 4697,
                    "ServiceFileName": f"%TEMP%\\noisy-{index}.exe",
                }
            )
        for _ in range(600, 5_000):
            writer.writerow({"EventID": 1, "ServiceFileName": ""})
        writer.writerow({"EventID": 1102, "ServiceFileName": ""})

    metadata = _meta(
        "service_install_4697",
        "clear_log_event",
        tool_id="evtxecmd",
    )
    metadata.suspicious_indicators[0].severity_baseline = "low"
    result = ExecutionResult(
        tool_id="evtxecmd",
        status="success",
        target_evidence="Security.evtx",
        artifacts=[
            OutputArtifact(
                path=str(output),
                role="generated",
                format="csv",
                size_bytes=output.stat().st_size,
            )
        ],
    )

    analysis = analyze_one(result, metadata, use_llm=False)

    assert len(analysis.findings) == 500
    assert analysis.findings[0].rule_id == "clear_log_event:1102"
    assert analysis.finding_limit_reached is True
    assert "finding_limit_reached=true" in analysis.summary


def _write_cross_batch_evtx_csv(
    output,
    *,
    failure_step_seconds: int,
    grouped_after_seconds: int,
    success_after_seconds: int,
    duplicate_terminals: bool = False,
):
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "EventID",
                "TimeCreated",
                "IpAddress",
                "TargetUserName",
                "MemberName",
                "TargetSid",
            ],
        )
        writer.writeheader()
        final_row = 10_002 if duplicate_terminals else 5_002
        for row_number in range(1, final_row + 1):
            row: dict[str, object] = {"EventID": 1}
            if 4_477 <= row_number <= 4_486:
                failure_number = row_number - 4_477
                row = {
                    "EventID": 4625,
                    "TimeCreated": (
                        start + timedelta(seconds=failure_number * failure_step_seconds)
                    ).isoformat(),
                    "IpAddress": "203.0.113.42",
                }
            elif row_number == 4_487:
                row = {
                    "EventID": 4720,
                    "TimeCreated": start.isoformat(),
                    "TargetUserName": "boundary-user",
                }
            elif row_number == 5_001:
                row = {
                    "EventID": 4732,
                    "TimeCreated": (
                        start + timedelta(seconds=grouped_after_seconds)
                    ).isoformat(),
                    "TargetUserName": "Administrators",
                    "MemberName": "boundary-user",
                    "TargetSid": "S-1-5-32-544",
                }
            elif row_number == 5_002:
                row = {
                    "EventID": 4624,
                    "TimeCreated": (
                        start + timedelta(seconds=success_after_seconds)
                    ).isoformat(),
                    "IpAddress": "203.0.113.42",
                }
            elif duplicate_terminals and row_number == 10_001:
                row = {
                    "EventID": 4732,
                    "TimeCreated": (
                        start + timedelta(seconds=grouped_after_seconds + 30)
                    ).isoformat(),
                    "TargetUserName": "Administrators",
                    "MemberName": "boundary-user",
                    "TargetSid": "S-1-5-32-544",
                }
            elif duplicate_terminals and row_number == 10_002:
                row = {
                    "EventID": 4624,
                    "TimeCreated": (
                        start + timedelta(seconds=success_after_seconds + 30)
                    ).isoformat(),
                    "IpAddress": "203.0.113.42",
                }
            writer.writerow(row)


def _analyze_cross_batch_evtx_csv(output):
    metadata = _meta(
        "failed_logon_burst",
        "brute_force_followed_by_success",
        "account_creation_4720",
        tool_id="evtxecmd",
    )
    result = ExecutionResult(
        tool_id="evtxecmd",
        status="success",
        target_evidence="Security.evtx",
        artifacts=[
            OutputArtifact(
                path=str(output),
                role="generated",
                format="csv",
                size_bytes=output.stat().st_size,
            )
        ],
    )
    return analyze_one(result, metadata, use_llm=False)


def test_evtx_correlations_survive_csv_batch_boundary(tmp_path):
    output = tmp_path / "boundary-events.csv"
    _write_cross_batch_evtx_csv(
        output,
        failure_step_seconds=1,
        grouped_after_seconds=60,
        success_after_seconds=60,
    )

    analysis = _analyze_cross_batch_evtx_csv(output)
    rule_ids = [finding.rule_id for finding in analysis.findings]

    assert rule_ids.count("failed_logon_burst") == 1
    assert rule_ids.count("brute_force_followed_by_success") == 1
    assert rule_ids.count("account_creation_4720") == 1
    assert analysis.finding_limit_reached is False


def test_evtx_cross_batch_carry_preserves_timestamp_windows(tmp_path):
    output = tmp_path / "stale-boundary-events.csv"
    _write_cross_batch_evtx_csv(
        output,
        failure_step_seconds=40,
        grouped_after_seconds=3_601,
        success_after_seconds=500,
    )

    analysis = _analyze_cross_batch_evtx_csv(output)

    assert analysis.findings == []
    assert analysis.finding_limit_reached is False


def test_evtx_cross_batch_carry_preserves_one_finding_per_principal(tmp_path):
    output = tmp_path / "duplicate-terminal-events.csv"
    _write_cross_batch_evtx_csv(
        output,
        failure_step_seconds=1,
        grouped_after_seconds=60,
        success_after_seconds=60,
        duplicate_terminals=True,
    )

    analysis = _analyze_cross_batch_evtx_csv(output)
    rule_ids = [finding.rule_id for finding in analysis.findings]

    assert rule_ids.count("brute_force_followed_by_success") == 1
    assert rule_ids.count("account_creation_4720") == 1


def test_evtx_correlation_families_isolate_floods_and_report_eviction(tmp_path):
    output = tmp_path / "correlation-family-flood.csv"
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "EventID",
                "TimeCreated",
                "IpAddress",
                "TargetUserName",
                "MemberName",
                "TargetSid",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "EventID": 4720,
                "TimeCreated": start.isoformat(),
                "TargetUserName": "isolated-account",
            }
        )
        for index in range(9_999):
            writer.writerow(
                {
                    "EventID": 4625,
                    "IpAddress": f"203.0.{index // 256}.{index % 256}",
                }
            )
        writer.writerow(
            {
                "EventID": 4732,
                "TimeCreated": (start + timedelta(seconds=60)).isoformat(),
                "TargetUserName": "Administrators",
                "MemberName": "isolated-account",
                "TargetSid": "S-1-5-32-544",
            }
        )

    analysis = _analyze_cross_batch_evtx_csv(output)

    assert [
        finding.rule_id
        for finding in analysis.findings
        if finding.rule_id == "account_creation_4720"
    ] == ["account_creation_4720"]
    assert "coverage_truncated=true" in analysis.summary
    assert "logon event correlation carry exceeded" in analysis.summary


def test_exact_final_correlation_carry_cap_does_not_claim_truncation(tmp_path):
    output = tmp_path / "exact-correlation-family-cap.csv"
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["EventID", "TargetUserName"])
        writer.writeheader()
        for index in range(10_000):
            writer.writerow(
                {"EventID": 4720, "TargetUserName": f"boundary-user-{index}"}
            )

    analysis = _analyze_cross_batch_evtx_csv(output)

    assert analysis.findings == []
    assert "coverage_truncated=true" not in analysis.summary


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
    llm_finding = next(f for f in analysis.findings if f.source == "llm")
    assert llm_finding.confidence == 0.6
    assert llm_finding.severity == "low"


class _MustNotRunClient:
    def json_chat(self, messages, **kwargs):
        raise AssertionError("code-security output must not be sent to an LLM")


def test_code_security_output_never_reaches_llm():
    metadata = _meta("gitleaks_secret", tool_id="gitleaks")
    metadata.category = "code_security"
    secret = "AKIAABCDEFGHIJKLMNOP"
    analysis = analyze_one(
        ExecutionResult(
            tool_id="gitleaks",
            status="success",
            target_evidence=".env",
            parsed_output=[
                {
                    "RuleID": "aws-access-token",
                    "File": ".env",
                    "StartLine": 1,
                    "Secret": secret,
                    "Match": f"AWS_ACCESS_KEY_ID={secret}",
                }
            ],
        ),
        metadata,
        use_llm=True,
        client=_MustNotRunClient(),
    )

    assert analysis.llm_invoked is False
    assert len(analysis.findings) == 1
    assert secret not in analysis.findings[0].evidence_ref.raw_excerpt


def test_oversized_csv_record_is_skipped_but_tail_is_analyzed(tmp_path):
    output = tmp_path / "events.csv"
    oversized = "x" * (csv.field_size_limit() + 1)
    output.write_text(
        "EventID,Payload\n"
        f'4625,"{oversized}"\n'
        '1102,"tail"\n',
        encoding="utf-8",
    )
    analysis = analyze_one(
        ExecutionResult(
            tool_id="evtxecmd",
            status="success",
            target_evidence="Security.evtx",
            artifacts=[
                OutputArtifact(
                    path=str(output),
                    role="generated",
                    format="csv",
                    size_bytes=output.stat().st_size,
                )
            ],
        ),
        _meta("clear_log_event", tool_id="evtxecmd"),
        use_llm=False,
    )

    assert {finding.rule_id for finding in analysis.findings} == {"clear_log_event:1102"}
    assert analysis.coverage_warnings


def test_wide_csv_record_cannot_exceed_batch_budget(tmp_path):
    output = tmp_path / "wide-events.csv"
    fields = ["EventID", *(f"Field{index}" for index in range(43))]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow({"EventID": 4625, **{name: "x" * 100_000 for name in fields[1:]}})
        writer.writerow({"EventID": 1102})

    analysis = analyze_one(
        ExecutionResult(
            tool_id="evtxecmd",
            status="success",
            target_evidence="Security.evtx",
            artifacts=[
                OutputArtifact(
                    path=str(output),
                    role="generated",
                    format="csv",
                    size_bytes=output.stat().st_size,
                )
            ],
        ),
        _meta("clear_log_event", tool_id="evtxecmd"),
        use_llm=False,
    )

    assert {finding.rule_id for finding in analysis.findings} == {"clear_log_event:1102"}
    assert any("record above" in warning for warning in analysis.coverage_warnings)


def test_oversized_cr_only_csv_record_keeps_tail_detection(tmp_path):
    output = tmp_path / "classic-mac-events.csv"
    output.write_bytes(
        (
            "EventID,Payload\r4625,"
            + ("x" * (CASE_B_MAX + 1))
            + "\r1102,tail\r"
        ).encode()
    )

    analysis = analyze_one(
        ExecutionResult(
            tool_id="evtxecmd",
            status="success",
            target_evidence="Security.evtx",
            artifacts=[
                OutputArtifact(
                    path=str(output),
                    role="generated",
                    format="csv",
                    size_bytes=output.stat().st_size,
                )
            ],
        ),
        _meta("clear_log_event", tool_id="evtxecmd"),
        use_llm=False,
    )

    assert {finding.rule_id for finding in analysis.findings} == {"clear_log_event:1102"}
    assert analysis.coverage_warnings


def test_large_jsonl_stream_keeps_tail_detection(tmp_path):
    output = tmp_path / "chainsaw.jsonl"
    benign = '{"EventID": 1, "padding": "' + ("x" * 90_000) + '"}\n'
    output.write_text(benign * 47 + '{"EventID": 1102}\n', encoding="utf-8")
    assert output.stat().st_size > CASE_B_MAX

    analysis = analyze_one(
        ExecutionResult(
            tool_id="chainsaw",
            status="success",
            target_evidence="renamed.evtx",
            artifacts=[
                OutputArtifact(
                    path=str(output),
                    role="generated",
                    format="jsonl",
                    size_bytes=output.stat().st_size,
                )
            ],
        ),
        _meta("clear_log_event", tool_id="chainsaw"),
        use_llm=False,
    )

    assert {finding.rule_id for finding in analysis.findings} == {"clear_log_event:1102"}
    assert analysis.case_used == "C"


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
