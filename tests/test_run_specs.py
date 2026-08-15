from __future__ import annotations

from pathlib import Path

from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector import RunSpec, select
from forensicagent.tools.loader import load_tool


_METADATA = Path(__file__).resolve().parents[1] / "tools_metadata"


def _evidence(path: Path, evidence_type: str) -> Evidence:
    return Evidence(
        path=str(path),
        filename=path.name,
        size_bytes=100,
        evidence_type=evidence_type,  # type: ignore[arg-type]
        detected_by="extension",
        confidence=0.9,
    )


def test_volatility_always_runs_pslist_and_full_triage_adds_plugins(tmp_path):
    metadata = load_tool(_METADATA / "volatility3.yaml")
    inventory = Inventory(
        evidence_list=[_evidence(tmp_path / "memory.raw", "memory_dump")]
    )

    default = select(
        inventory,
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
    ).selected_tools[0]
    full = select(
        inventory,
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
        scenario="full triage for suspicious network and memory injection",
    ).selected_tools[0]

    assert [spec.label for spec in default.run_specs] == ["pslist", "cmdline"]
    assert [spec.label for spec in full.run_specs] == [
        "pslist",
        "cmdline",
        "netscan",
        "malfind",
        "pstree",
    ]
    assert all(spec.target_evidence.endswith("memory.raw") for spec in full.run_specs)


def test_volatility_scenario_adds_only_requested_plugin(tmp_path):
    metadata = load_tool(_METADATA / "volatility3.yaml")
    inventory = Inventory(
        evidence_list=[_evidence(tmp_path / "capture.vmem", "memory_dump")]
    )

    selection = select(
        inventory,
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
        scenario="Investigate unusual network connections",
    ).selected_tools[0]

    assert [spec.label for spec in selection.run_specs] == [
        "pslist", "cmdline", "netscan"
    ]


def test_regripper_selects_plugin_by_hive_basename(tmp_path):
    metadata = load_tool(_METADATA / "regripper.yaml")
    names = ["NTUSER.DAT", "SYSTEM", "SOFTWARE", "SECURITY", "SAM"]
    inventory = Inventory(
        evidence_list=[
            _evidence(tmp_path / name, "registry_hive") for name in names
        ]
    )

    selection = select(
        inventory,
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
    ).selected_tools[0]

    by_name = {
        Path(spec.target_evidence).name: spec for spec in selection.run_specs
    }
    assert "-p userassist" in by_name["NTUSER.DAT"].command_template
    assert "-p services" in by_name["SYSTEM"].command_template
    assert "-p run" in by_name["SOFTWARE"].command_template
    assert by_name["SECURITY"].variables == {"profile": "security"}
    assert by_name["SAM"].variables == {"profile": "sam"}
    assert isinstance(selection.run_specs[0], RunSpec)
    assert selection.to_dict()["run_specs"][0]["command_template"]
