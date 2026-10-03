"""Tests for Alembic database migrations."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_alembic_upgrade_and_downgrade(tmp_path: Path):
    """Verify that Alembic can run upgrade to head and downgrade to base."""
    db_file = tmp_path / "migration_test.db"
    async_db_url = f"sqlite+aiosqlite:///{db_file}"
    sync_db_url = f"sqlite:///{db_file}"

    root_dir = Path(__file__).parent.parent.parent
    ini_path = root_dir / "alembic.ini"

    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(root_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", async_db_url)

    # 1. Upgrade to head
    command.upgrade(cfg, "head")

    # Verify tables created
    sync_engine = create_engine(sync_db_url)

    inspector = inspect(sync_engine)
    table_names = set(inspector.get_table_names())

    assert "projects" in table_names
    assert "vulnerabilities" in table_names
    assert "matches" in table_names
    assert "scans" in table_names
    assert "project_components" in table_names
    assert "vulnerability_sources" in table_names
    assert "ai_analyses" in table_names
    assert "decision_results" in table_names
    assert "risk_assessments" in table_names
    assert "vulnerability_identifiers" in table_names
    assert "vulnerability_source_records" in table_names
    assert "vulnerability_affected_ranges" in table_names
    assert "match_evidences" in table_names
    assert "source_conflicts" in table_names
    assert "dependency_edges" in table_names
    assert "policies" in table_names
    assert "policy_rules" in table_names
    assert "suppressions" in table_names
    assert "policy_evaluations" in table_names
    assert "container_images" in table_names
    assert "container_layers" in table_names
    assert "container_image_components" in table_names
    assert "alembic_version" in table_names

    # Verify column canonical_id in vulnerabilities
    vuln_cols = {c["name"] for c in inspector.get_columns("vulnerabilities")}
    assert "canonical_id" in vuln_cols
    assert "severity" in vuln_cols
    assert "cvss_score" in vuln_cols

    # Verify dependency intelligence columns in project_components
    comp_cols = {c["name"] for c in inspector.get_columns("project_components")}
    assert "is_direct" in comp_cols
    assert "dependency_type" in comp_cols
    assert "scope" in comp_cols
    assert "manifest_source" in comp_cols
    assert "lockfile_source" in comp_cols
    assert "parent_name" in comp_cols
    assert "dependency_path" in comp_cols

    # Verify dependency_edges columns
    edge_cols = {c["name"] for c in inspector.get_columns("dependency_edges")}
    assert "parent_name" in edge_cols
    assert "child_name" in edge_cols
    assert "scope" in edge_cols
    assert "requirement" in edge_cols

    sync_engine.dispose()

    # 2. Downgrade back to base
    command.downgrade(cfg, "base")

    # Verify tables removed
    sync_engine = create_engine(sync_db_url)
    inspector = inspect(sync_engine)

    remaining_tables = set(inspector.get_table_names()) - {"alembic_version"}
    assert len(remaining_tables) == 0

    sync_engine.dispose()


def test_alembic_data_migration_cve_to_canonical(tmp_path: Path):
    """Verify that existing cve_id records are migrated to canonical_id and identifiers."""
    db_file = tmp_path / "data_migration_test.db"
    async_db_url = f"sqlite+aiosqlite:///{db_file}"
    sync_db_url = f"sqlite:///{db_file}"

    root_dir = Path(__file__).parent.parent.parent
    ini_path = root_dir / "alembic.ini"

    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(root_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", async_db_url)

    # 1. Upgrade to pre-stage 3 (c624ffe1d77b)
    command.upgrade(cfg, "c624ffe1d77b")

    from sqlalchemy import text

    sync_engine = create_engine(sync_db_url)
    with sync_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO vulnerability_sources (id, name, source_type, url, status, record_count) "
                "VALUES ('src-1', 'CISA KEV', 'kev', 'http://example.com', 'active', 1)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO vulnerabilities (id, cve_id, source_id, vendor_project, product, "
                "vulnerability_name, short_description, required_action, known_ransomware_use, cwes, notes, synced_at) "
                "VALUES ('vuln-1', 'CVE-2024-9999', 'src-1', 'TestVendor', 'TestProd', "
                "'Test Name', 'Short Desc', 'Fix it', 'Known', '[]', '', '2026-01-01 00:00:00')"
            )
        )
    sync_engine.dispose()

    # 3. Upgrade to head (e7a1b3c9d2f4)
    command.upgrade(cfg, "head")

    # 4. Verify canonical_id and backfilled identifiers & source records
    sync_engine = create_engine(sync_db_url)
    with sync_engine.connect() as conn:
        vuln_row = conn.execute(
            text("SELECT canonical_id, cve_id FROM vulnerabilities WHERE id = 'vuln-1'")
        ).fetchone()
        assert vuln_row is not None
        assert vuln_row[0] == "CVE-2024-9999"
        assert vuln_row[1] == "CVE-2024-9999"

        ident_rows = conn.execute(
            text(
                "SELECT identifier, identifier_type, source FROM vulnerability_identifiers WHERE vulnerability_id = 'vuln-1'"
            )
        ).fetchall()
        assert len(ident_rows) == 1
        assert ident_rows[0][0] == "CVE-2024-9999"
        assert ident_rows[0][1] == "cve"

        src_rows = conn.execute(
            text(
                "SELECT source_name, source_identifier, has_kev_evidence FROM vulnerability_source_records WHERE vulnerability_id = 'vuln-1'"
            )
        ).fetchall()
        assert len(src_rows) == 1
        assert src_rows[0][0] == "CISA KEV"
        assert src_rows[0][1] == "CVE-2024-9999"
        assert src_rows[0][2] == 1

    sync_engine.dispose()
