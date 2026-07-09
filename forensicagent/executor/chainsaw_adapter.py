"""Chainsaw 전용 어댑터 — EVTX 채널별 올바른 Event ID 검색.

왜 필요한가 (GenericAdapter 로는 안 되는 이유):
  * chainsaw `search -e` 는 "Event ID 리스트"가 아니라 **단일 정규식**이다.
    쉼표는 OR 가 아니라 리터럴 문자라서 `-e 4624,4625,4104` 는 그 문자열이
    통째로 들어간 레코드를 찾다가 0 hits 로 끝난다. 여러 ID 를 보려면
    정규식 alternation `-e "4624|4625"` 로 묶어야 한다.
  * 게다가 Event ID 는 채널(파일)마다 저장되는 종류가 다르다.
      - Security.evtx                                → 4624(로그온 성공) / 4625(실패)
      - Microsoft-Windows-PowerShell%4Operational.evtx → 4104(스크립트블록)
    모든 evtx 에 같은 ID 를 검색하면 엉뚱한 파일엔 항상 0 hits 다.

그래서 이 어댑터는 **증거 파일명으로 채널을 판별해, 그 채널에 실제로
기록되는 Event ID 만** alternation 으로 묶어 evidence 당 chainsaw 를 1 회
실행한다 (executor 의 "evidence 1 개 = argv 1 개" 모델 그대로 유지).

주의: `-e` 는 직렬화된 레코드 텍스트 전체에 대한 regex 매칭이라 한 자리
Event ID(예: Sysmon 1/3)를 넣으면 "1" 이 아무 데나 매칭돼 오탐이 폭증한다.
따라서 여기 매핑에는 **구분력 있는 4 자리 ID 만** 둔다. 정밀 매칭이
필요하면 chainsaw Tau (`-t 'Event.System.EventID: =4624'`) 로 갈아끼우면 된다.
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensicagent.executor.adapter import GenericAdapter

logger = logging.getLogger(__name__)


# 채널(파일) → 그 채널에서 의미 있는 Event ID 목록.
# 새 채널을 지원하려면 여기에 (판별 토큰, ID 리스트) 한 줄만 추가하면 된다.
CHANNEL_EVENT_IDS: dict[str, list[str]] = {
    # Security.evtx — 로그온 성공(4624) / 실패(4625)
    "security": ["4624", "4625"],
    # Microsoft-Windows-PowerShell%4Operational.evtx — 스크립트블록 로깅(4104)
    # (모듈 로깅 4103 도 유용하면 여기에 추가: ["4104", "4103"])
    "powershell": ["4104"],
}

# 채널을 특정하지 못한 evtx 는 로그온 이벤트만 훑는다 (가장 범용적).
DEFAULT_EVENT_IDS: list[str] = ["4624", "4625"]


def event_ids_for_file(filename: str) -> list[str]:
    """파일명으로 채널을 추정해 검색할 Event ID 목록을 돌려준다."""
    f = filename.lower()
    # PowerShell Operational 이 먼저 (파일명에 'security' 가 없으므로 순서 무관하지만 명시).
    if "powershell" in f and "operational" in f:
        return CHANNEL_EVENT_IDS["powershell"]
    if "security" in f:
        return CHANNEL_EVENT_IDS["security"]
    return DEFAULT_EVENT_IDS


class ChainsawAdapter(GenericAdapter):
    """파일별 Event ID 를 alternation regex 로 묶어 chainsaw search 를 만든다."""

    def build_command(self, evidence_path: str, **vars: str) -> list[str]:
        ids = event_ids_for_file(Path(evidence_path).name)
        pattern = "|".join(ids)
        logger.info(
            "chainsaw: %s → -e %r", Path(evidence_path).name, pattern
        )
        # shell=False 로 그대로 넘어가므로 공백 있는 경로도 argv 원소 1 개로 안전.
        return [
            "chainsaw",
            "search",
            evidence_path,
            "-e",
            pattern,
            "--json",
        ]
