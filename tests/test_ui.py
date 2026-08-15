from forensicagent.cli.ui import render_inventory
from forensicagent.scanner.types import Evidence, Inventory


def test_inventory_preview_is_bounded():
    inventory = Inventory(
        evidence_list=[
            Evidence(
                path=f"/{i}.py",
                filename=f"{i}.py",
                size_bytes=1,
                evidence_type="source_code_python",
                detected_by="extension",
            )
            for i in range(35)
        ]
    )

    table = render_inventory(inventory, max_rows=10)

    assert table.row_count == 10
    assert table.caption is not None
    assert "showing 10 of 35" in table.caption
