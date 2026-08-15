"""Deterministic per-target command expansion for multi-pass tools.

Most tools need one command per evidence file.  Memory and registry analysis
are different: useful coverage requires selecting a plugin as well as a tool,
and the safe plugin depends on the scenario or hive basename.  This module
keeps that decision in the selector layer instead of hard-coding tool behavior
inside the subprocess executor.
"""

from __future__ import annotations

import re
from pathlib import Path, PureWindowsPath

from forensicagent.selector.types import RunSpec, ToolSelection
from forensicagent.tools.schema import ToolMetadata


_FULL_TRIAGE_TERMS = (
    "full triage",
    "full intrusion triage",
    "full host triage",
    "full memory triage",
    "comprehensive triage",
    "complete triage",
    "전체 트리아지",
    "전체 분석",
    "종합 분석",
    "정밀 분석",
)

_SCENARIO_TERMS: dict[str, tuple[str, ...]] = {
    "netscan": (
        "netscan",
        "network",
        "network connection",
        "네트워크",
        "외부 통신",
        "c2 통신",
    ),
    "malfind": (
        "malfind",
        "memory injection",
        "injected code",
        "코드 주입",
        "메모리 주입",
    ),
    "pstree": (
        "pstree",
        "process tree",
        "parent child",
        "parent-child",
        "프로세스 트리",
        "부모 자식",
    ),
}

_VOLATILITY_MARKERS = {
    "pslist": "windows.pslist.",
    "cmdline": "windows.cmdline.",
    "netscan": "windows.netscan.",
    "malfind": "windows.malfind.",
    "pstree": "windows.pstree.",
}

_REGRIPPER_MARKERS = {
    "ntuser.dat": ("userassist", "-p userassist"),
    "system": ("services", "-p services"),
    "software": ("run", "-p run"),
}


def populate_run_specs(
    selections: list[ToolSelection],
    tools: dict[str, ToolMetadata],
    scenario: str | None,
) -> None:
    """Attach concrete run specs in place, preserving explicit caller specs."""
    for selection in selections:
        if selection.run_specs:
            continue
        metadata = tools.get(selection.tool_id)
        if metadata is None:
            selection.run_specs = _legacy_specs(selection)
        elif selection.tool_id == "volatility3":
            selection.run_specs = _volatility_specs(selection, metadata, scenario)
        elif selection.tool_id == "regripper":
            selection.run_specs = _regripper_specs(selection, metadata)
        else:
            selection.run_specs = _legacy_specs(selection)


def _legacy_specs(selection: ToolSelection) -> list[RunSpec]:
    return [
        RunSpec(
            target_evidence=target,
            command_template=selection.command_template,
        )
        for target in dict.fromkeys(selection.target_evidence)
    ]


def _volatility_specs(
    selection: ToolSelection,
    metadata: ToolMetadata,
    scenario: str | None,
) -> list[RunSpec]:
    # pslist provides process identity/parent linkage; cmdline provides paths
    # and arguments needed by the unusual-path detector. Both are cheap core
    # passes, while network/injection/tree plugins remain scenario-driven.
    plugins = ["pslist", "cmdline", *_scenario_plugins(scenario)]
    templates: list[tuple[str, str]] = []
    for plugin in dict.fromkeys(plugins):
        template = _template_containing(metadata, _VOLATILITY_MARKERS[plugin])
        if template is None and plugin == "pslist":
            template = selection.command_template
        if template:
            templates.append((plugin, template))

    return [
        RunSpec(
            target_evidence=target,
            command_template=template,
            label=plugin,
        )
        for target in dict.fromkeys(selection.target_evidence)
        for plugin, template in templates
    ]


def _scenario_plugins(scenario: str | None) -> list[str]:
    if not scenario or not scenario.strip():
        return []
    normalized = re.sub(r"[_-]+", " ", scenario.casefold())
    if any(term in normalized for term in _FULL_TRIAGE_TERMS):
        return ["netscan", "malfind", "pstree"]
    return [
        plugin
        for plugin, terms in _SCENARIO_TERMS.items()
        if any(term in normalized for term in terms)
    ]


def _regripper_specs(
    selection: ToolSelection,
    metadata: ToolMetadata,
) -> list[RunSpec]:
    specs: list[RunSpec] = []
    profile_template = _template_containing(metadata, "{profile}")
    for target in dict.fromkeys(selection.target_evidence):
        hive = _basename(target).casefold()
        mapped = _REGRIPPER_MARKERS.get(hive)
        if mapped is not None:
            label, marker = mapped
            template = _template_containing(metadata, marker)
            specs.append(
                RunSpec(
                    target_evidence=target,
                    command_template=template or selection.command_template,
                    label=label,
                )
            )
            continue

        # SECURITY and SAM are supported by RegRipper profiles but do not map
        # to the three focused plugins above.  Use the metadata-declared full
        # profile template when present instead of applying userassist blindly.
        if hive in {"security", "sam"} and profile_template:
            specs.append(
                RunSpec(
                    target_evidence=target,
                    command_template=profile_template,
                    variables={"profile": hive},
                    label=f"{hive}-profile",
                )
            )
            continue

        specs.append(
            RunSpec(
                target_evidence=target,
                command_template=selection.command_template,
            )
        )
    return specs


def _template_containing(metadata: ToolMetadata, marker: str) -> str | None:
    folded = marker.casefold()
    for command in metadata.command_templates:
        if folded in command.template.casefold():
            return command.template
    return None


def _basename(path: str) -> str:
    name = Path(path).name
    if "\\" in name:
        return PureWindowsPath(path).name
    return name


__all__ = ["populate_run_specs"]
