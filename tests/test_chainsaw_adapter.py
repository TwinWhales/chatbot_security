"""ChainsawAdapter — 파일(채널)별 Event ID 타겟팅 + alternation regex 테스트.

핵심 회귀 방지 대상:
  * chainsaw `-e` 는 단일 정규식이라 여러 ID 는 alternation `4624|4625` 로
    묶어야 한다 (쉼표 리스트 `4624,4625` 는 0 hits — 이게 원래 버그).
  * Event ID 는 채널마다 다르다: 4624/4625 는 Security, 4104 는 PowerShell
    Operational. 파일명으로 올바른 ID 를 골라야 한다.

LLM / 네트워크 없이 결정론적으로 검증한다.
"""

from __future__ import annotations

from forensicagent.executor.adapter import get_adapter
from forensicagent.executor.chainsaw_adapter import (
    ChainsawAdapter,
    event_ids_for_file,
)
from forensicagent.tools.schema import CommandTemplate, InstallCheck, ToolMetadata


def _chainsaw_meta() -> ToolMetadata:
    return ToolMetadata(
        tool_id="chainsaw",
        display_name="Chainsaw",
        category="log_analysis",
        applicable_evidence_types=["evtx_log"],  # type: ignore[arg-type]
        command_templates=[
            CommandTemplate(
                name="search",
                template="chainsaw search {evidence_path} -e {event_ids} --json",
                when="특정 Event ID 검색.",
            )
        ],
        install_check=InstallCheck(
            command="chainsaw --version", expected_pattern="chainsaw"
        ),
        output_format="json",
        usage_description="Windows EVTX hunting.",
    )


# ---- channel → event id mapping ----

def test_security_channel_gets_logon_ids():
    assert event_ids_for_file("Security.evtx") == ["4624", "4625"]


def test_powershell_channel_gets_scriptblock_id():
    assert event_ids_for_file(
        "Microsoft-Windows-PowerShell%4Operational.evtx"
    ) == ["4104"]


def test_channel_detection_is_case_insensitive():
    assert event_ids_for_file("security.EVTX") == ["4624", "4625"]


def test_powershell_takes_precedence_and_is_not_treated_as_security():
    # PowerShell 파일명엔 'security' 가 없어 로그온 ID 로 새지 않아야 한다.
    ids = event_ids_for_file("microsoft-windows-powershell%4operational.evtx")
    assert ids == ["4104"]


def test_unknown_channel_falls_back_to_logon_ids():
    assert event_ids_for_file("Application.evtx") == ["4624", "4625"]


# ---- command building ----

def test_registry_wires_chainsaw_to_specialized_adapter():
    adapter = get_adapter(_chainsaw_meta())
    assert isinstance(adapter, ChainsawAdapter)


def test_build_command_uses_alternation_not_comma():
    adapter = ChainsawAdapter(_chainsaw_meta())
    argv = adapter.build_command(r"C:\ev\Security.evtx", output_dir="out")
    assert argv == [
        "chainsaw", "search", r"C:\ev\Security.evtx",
        "-e", "4624|4625", "--json",
    ]
    # 쉼표(0 hits 버그)가 절대 들어가면 안 된다.
    joined = " ".join(argv)
    assert "4624,4625" not in joined
    assert "|" in argv[argv.index("-e") + 1]


def test_build_command_per_file_event_ids():
    adapter = ChainsawAdapter(_chainsaw_meta())
    ps = adapter.build_command(
        r"C:\ev\Microsoft-Windows-PowerShell%4Operational.evtx",
        output_dir="out",
    )
    assert ps[ps.index("-e") + 1] == "4104"


def test_path_with_spaces_stays_single_argv_element():
    adapter = ChainsawAdapter(_chainsaw_meta())
    argv = adapter.build_command(r"C:\eviing dir\Security.evtx", output_dir="o")
    assert r"C:\eviing dir\Security.evtx" in argv
