"""포렌식 도구 설치 도우미 — pip / zip 다운 / manual 안내.

doctor 가 "miss" 라고 잡은 도구를 자동(가능한 경우) 또는 안내(URL+curl
예시) 로 채워 준다.

Registry 한 곳에 모든 메타데이터:
- kind="pip"     : `pip install <package>` 로 해결
- kind="zip"     : URL 에서 zip 받아 ~/.forensicagent/tools_bin/<name>/ 로 풂
- kind="manual"  : 자동 설치 불가, URL 만 안내 (라이선스/설치 마법사/큰 의존성)

설치된 zip 도구의 실행파일은 ~/.forensicagent/tools_bin/<name>/<exe> 에 있고,
doctor 의 PATH 검사가 이 디렉토리들도 자동으로 본다.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

from rich.console import Console

from forensicagent import config as settings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass
class ToolSpec:
    name: str                          # shutil.which 가 찾을 실행파일명
    kind: Literal["pip", "zip", "manual"]
    description: str
    homepage: str
    # pip
    pip_package: Optional[str] = None
    # zip
    zip_url: Optional[str] = None
    zip_executable: Optional[str] = None  # zip 안에서 찾을 .exe 파일명
    # manual
    manual_hint: str = ""
    # platform restriction
    only_on: Optional[str] = None      # "win32" | "linux" | "darwin"


# Windows 가 1순위, Linux/macOS 는 차차 보강.
TOOL_SPECS: dict[str, ToolSpec] = {
    # ---- pip 으로 설치 가능 ----
    "vol": ToolSpec(
        name="vol",
        kind="pip",
        description="Volatility3 - memory forensics framework",
        homepage="https://github.com/volatilityfoundation/volatility3",
        pip_package="volatility3",
    ),
    "volatility3": ToolSpec(
        name="volatility3",
        kind="pip",
        description="(alias) installed alongside vol",
        homepage="https://github.com/volatilityfoundation/volatility3",
        pip_package="volatility3",
    ),
    "binwalk": ToolSpec(
        name="binwalk",
        kind="pip",
        description="Firmware/embedded object extraction",
        homepage="https://github.com/ReFirmLabs/binwalk",
        pip_package="binwalk",
    ),
    "bandit": ToolSpec(
        name="bandit",
        kind="pip",
        description="Python SAST - OWASP/CWE 패턴 탐지",
        homepage="https://bandit.readthedocs.io/",
        pip_package="bandit",
    ),
    "semgrep": ToolSpec(
        name="semgrep",
        kind="pip",
        description="Multi-language SAST - auto ruleset",
        homepage="https://semgrep.dev/",
        pip_package="semgrep",
    ),

    # ---- zip 다운로드 가능 (GitHub releases) ----
    # /releases/latest/download/ 패턴으로 자산 파일명이 안정적인 경우만.
    "chainsaw": ToolSpec(
        name="chainsaw",
        kind="zip",
        description="EVTX hunt with Sigma rules",
        homepage="https://github.com/WithSecureLabs/chainsaw",
        zip_url="https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-pc-windows-msvc.zip",
        zip_executable="chainsaw.exe",
        only_on="win32",
    ),
    "gitleaks": ToolSpec(
        name="gitleaks",
        kind="manual",
        description="Secret scanner - API keys / credentials in code",
        homepage="https://github.com/gitleaks/gitleaks/releases",
        # GitHub release asset 파일명에 버전이 들어가 latest/download 패턴 불가.
        # 사용자가 직접 받아 ~/.forensicagent/tools_bin/gitleaks/gitleaks.exe 로.
        manual_hint=(
            "Windows: download gitleaks_X.Y.Z_windows_x64.zip from GitHub releases, "
            "extract gitleaks.exe to ~/.forensicagent/tools_bin/gitleaks/. "
            "또는 `choco install gitleaks` / `scoop install gitleaks`."
        ),
    ),

    # ---- manual (라이선스/설치 마법사/MSVC 빌드 필요/버전 변동 큰 URL) ----
    "plaso": ToolSpec(
        name="plaso",
        kind="manual",
        description="log2timeline super-timeline",
        homepage="https://plaso.readthedocs.io/en/latest/sources/user/Users-Guide.html",
        manual_hint=(
            "Windows: needs MSVC Build Tools first "
            "(https://visualstudio.microsoft.com/visual-cpp-build-tools/), "
            "then `pip install plaso`. Or use the Docker image."
        ),
    ),
    "log2timeline.py": ToolSpec(
        name="log2timeline.py",
        kind="manual",
        description="part of plaso",
        homepage="https://plaso.readthedocs.io/",
        manual_hint="installed alongside plaso",
    ),
    "psort.py": ToolSpec(
        name="psort.py",
        kind="manual",
        description="part of plaso",
        homepage="https://plaso.readthedocs.io/",
        manual_hint="installed alongside plaso",
    ),
    "yara": ToolSpec(
        name="yara",
        kind="manual",
        description="Pattern matching for malware classification",
        homepage="https://github.com/VirusTotal/yara/releases",
        manual_hint=(
            "Download the latest yara-vX.Y.Z-*-win64.zip from GitHub releases, "
            "extract yara.exe to a directory on PATH (or to "
            "~/.forensicagent/tools_bin/yara/)."
        ),
    ),
    "exiftool": ToolSpec(
        name="exiftool",
        kind="manual",
        description="File metadata reader",
        homepage="https://exiftool.org/",
        manual_hint=(
            "Windows: download exiftool-XX.XX_64.zip from exiftool.org, "
            "rename the .exe to exiftool.exe, move to ~/.forensicagent/tools_bin/exiftool/."
        ),
    ),
    "tshark": ToolSpec(
        name="tshark",
        kind="manual",
        description="Wireshark CLI - pcap analysis",
        homepage="https://www.wireshark.org/download.html",
        manual_hint="Install full Wireshark (.exe installer); tshark.exe goes to C:\\Program Files\\Wireshark\\.",
    ),
    "tcpdump": ToolSpec(
        name="tcpdump",
        kind="manual",
        description="(Linux/macOS only)",
        homepage="https://www.tcpdump.org/",
        manual_hint="Linux: `apt install tcpdump`. macOS: bundled. Not native on Windows (use tshark).",
        only_on="linux",
    ),
    "rip": ToolSpec(
        name="rip",
        kind="manual",
        description="RegRipper",
        homepage="https://github.com/keydet89/RegRipper3.0",
        manual_hint=(
            "git clone https://github.com/keydet89/RegRipper3.0 into "
            "~/.forensicagent/tools_bin/regripper/, then add to PATH."
        ),
    ),
    "strings": ToolSpec(
        name="strings",
        kind="manual",
        description="Binary string extraction",
        homepage="https://learn.microsoft.com/en-us/sysinternals/downloads/strings",
        manual_hint="Windows: Sysinternals Strings or use Git Bash's strings.exe. Linux/macOS: usually bundled.",
    ),
}


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


def _tools_bin_root() -> Path:
    """Zip 추출 도구가 설치되는 디렉토리."""
    root = Path(settings.USER_HOME) / "tools_bin"
    return root


def installed_bin_dirs() -> list[Path]:
    """tools_bin 의 모든 하위 디렉토리. doctor 의 PATH 보강용."""
    root = _tools_bin_root()
    if not root.exists():
        return []
    return [p for p in root.iterdir() if p.is_dir()]


def find_executable(name: str) -> Optional[str]:
    """PATH + tools_bin 양쪽에서 도구 찾기."""
    p = shutil.which(name)
    if p:
        return p
    for bin_dir in installed_bin_dirs():
        # 정확 매치 우선
        for ext in ("", ".exe", ".bat"):
            cand = bin_dir / f"{name}{ext}"
            if cand.is_file():
                return str(cand)
        # 재귀 한 단계 (chainsaw 같은 일부 zip 은 chainsaw/chainsaw/chainsaw.exe 식)
        for sub in bin_dir.iterdir():
            if sub.is_dir():
                for ext in ("", ".exe", ".bat"):
                    cand = sub / f"{name}{ext}"
                    if cand.is_file():
                        return str(cand)
    return None


# ---------------------------------------------------------------------------
# Installers
# ---------------------------------------------------------------------------


def _platform_ok(spec: ToolSpec) -> bool:
    if spec.only_on is None:
        return True
    return sys.platform == spec.only_on or (
        spec.only_on == "linux" and sys.platform.startswith("linux")
    )


def install_pip(spec: ToolSpec, c: Console) -> bool:
    if not spec.pip_package:
        c.print(f"[red]{spec.name}: pip_package not set in registry[/]")
        return False
    c.print(f"[*] pip install {spec.pip_package} ...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", spec.pip_package],
            check=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        c.print(f"[red]pip install 실패 (exit {e.returncode}). {spec.manual_hint or ''}[/]")
        if spec.homepage:
            c.print(f"[dim]참고: {spec.homepage}[/]")
        return False


def install_zip(spec: ToolSpec, c: Console) -> bool:
    if not spec.zip_url:
        c.print(f"[red]{spec.name}: zip_url not set[/]")
        return False
    target_dir = _tools_bin_root() / spec.name
    target_dir.mkdir(parents=True, exist_ok=True)

    c.print(f"[*] 다운로드: {spec.zip_url}")
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        # urllib 가 stdlib 라서 추가 의존성 없음. 큰 파일에도 OK.
        with urllib.request.urlopen(spec.zip_url) as resp, tmp_path.open("wb") as f:
            shutil.copyfileobj(resp, f)
        c.print(f"[*] 풀기: {tmp_path} -> {target_dir}")
        with zipfile.ZipFile(tmp_path) as z:
            z.extractall(target_dir)
        tmp_path.unlink(missing_ok=True)
    except (urllib.error.URLError, OSError, zipfile.BadZipFile) as e:
        c.print(f"[red]다운/풀기 실패:[/] {e}")
        c.print(f"[dim]수동 다운: {spec.zip_url}[/]")
        return False

    found = find_executable(spec.zip_executable or spec.name)
    if found:
        c.print(f"[green]ok[/] {spec.name} -> {found}")
        return True
    else:
        c.print(
            f"[yellow]풀었지만 {spec.zip_executable or spec.name} 을 못 찾음. "
            f"{target_dir} 안을 직접 확인하세요.[/]"
        )
        return False


def show_manual(spec: ToolSpec, c: Console) -> None:
    c.print(f"[bold yellow]수동 설치 필요:[/] {spec.name}")
    c.print(f"  설명: {spec.description}")
    c.print(f"  안내: {spec.manual_hint or '(없음)'}")
    c.print(f"  URL : {spec.homepage}")
    # curl 예시 - 다운만이라도 도와줌
    if spec.zip_url:
        c.print(f"  [dim]curl -L -o {spec.name}.zip {spec.zip_url}[/]")


def install_one(spec: ToolSpec, c: Console) -> bool:
    """단일 도구 설치 시도. 성공/실패 bool."""
    if not _platform_ok(spec):
        c.print(f"[dim]{spec.name}: {sys.platform} 플랫폼 비대상 (only_on={spec.only_on})[/]")
        return False
    if find_executable(spec.name):
        c.print(f"[green]이미 설치됨:[/] {spec.name}")
        return True
    if spec.kind == "pip":
        return install_pip(spec, c)
    elif spec.kind == "zip":
        return install_zip(spec, c)
    else:  # manual
        show_manual(spec, c)
        return False


# ---------------------------------------------------------------------------
# Interactive flow
# ---------------------------------------------------------------------------


def _ask_yn(c: Console, prompt: str, default: bool = True) -> bool:
    if not sys.stdin.isatty():
        c.print(f"[dim]{prompt} (non-tty, default={'y' if default else 'n'})[/]")
        return default
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        ans = c.input(f"{prompt} {suffix} ").strip().lower()
    except EOFError:
        c.print(f"[dim](EOF, default={'y' if default else 'n'})[/]")
        return default
    if not ans:
        return default
    return ans in ("y", "yes")


def install_interactive(c: Console, names: Optional[list[str]] = None) -> int:
    """missing 도구를 하나씩 순회하며 y/n 으로 설치.

    names 가 주어지면 그것만, 아니면 registry 전체 중 missing 만.
    반환: 설치 성공 개수.
    """
    if names:
        # 별칭 정리 + registry 검증.
        targets = []
        for n in names:
            if n in TOOL_SPECS:
                targets.append(TOOL_SPECS[n])
            else:
                c.print(f"[red]registry 에 없는 도구:[/] {n}")
        if not targets:
            return 0
    else:
        # vol 과 volatility3 같은 별칭 중복 제거 — pip_package 기준.
        seen_pkg: set[str] = set()
        targets = []
        for spec in TOOL_SPECS.values():
            key = spec.pip_package or spec.zip_url or spec.name
            if key in seen_pkg:
                continue
            seen_pkg.add(key)
            if find_executable(spec.name) is None and _platform_ok(spec):
                targets.append(spec)
        if not targets:
            c.print("[green]모두 설치되어 있거나 현재 플랫폼 비대상입니다.[/]")
            return 0

    c.print(f"[bold]설치 후보 {len(targets)} 개[/]")
    for s in targets:
        kind_label = {"pip": "pip", "zip": "zip 다운", "manual": "수동"}[s.kind]
        c.print(f"  - [bold]{s.name}[/] ({kind_label}) - {s.description}")
    c.print("")

    installed = 0
    for spec in targets:
        c.print(f"\n--- {spec.name} ---")
        c.print(f"  {spec.description}")
        c.print(f"  homepage: {spec.homepage}")
        if spec.kind == "pip":
            prompt = f"pip install {spec.pip_package} 진행할까요?"
        elif spec.kind == "zip":
            prompt = f"{spec.zip_url} 다운로드할까요?"
        else:
            prompt = "수동 설치 안내만 보시겠어요?"
        if _ask_yn(c, prompt, default=True):
            if install_one(spec, c):
                installed += 1
        else:
            c.print("[dim]건너뜀.[/]")
    return installed


def install_all_auto(c: Console) -> int:
    """pip/zip 으로 자동 설치 가능한 모든 미설치 도구를 install. manual 은 안내만."""
    installed = 0
    seen_pkg: set[str] = set()
    for spec in TOOL_SPECS.values():
        key = spec.pip_package or spec.zip_url or spec.name
        if key in seen_pkg:
            continue
        seen_pkg.add(key)
        if find_executable(spec.name) is not None:
            continue
        if not _platform_ok(spec):
            continue
        c.print(f"\n--- {spec.name} ---")
        if spec.kind == "manual":
            show_manual(spec, c)
            continue
        if install_one(spec, c):
            installed += 1
    return installed
