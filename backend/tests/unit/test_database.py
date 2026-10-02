"""Tests for the database layer (repositories)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from vuln_ai.core.models import (
    DetectedComponent,
    Ecosystem,
    SourceStatus,
    VersionType,
    VulnerabilityRecord,
)
from vuln_ai.db.repositories import (
    ComponentRepository,
    ProjectRepository,
    ScanRepository,
    SourceRepository,
    VulnerabilityRepository,
)


class TestProjectRepository:
    """Tests for ProjectRepository."""

    async def test_create_project(self, db_session: AsyncSession):
        repo = ProjectRepository(db_session)
        project = await repo.create(
            name="test-project",
            path="/tmp/test",
            description="A test project",
        )
        assert project.id is not None
        assert project.name == "test-project"
        assert project.path == "/tmp/test"

    async def test_get_by_id(self, db_session: AsyncSession):
        repo = ProjectRepository(db_session)
        created = await repo.create(name="test", path="/tmp/test")
        found = await repo.get_by_id(created.id)
        assert found is not None
        assert found.name == "test"

    async def test_get_by_id_not_found(self, db_session: AsyncSession):
        repo = ProjectRepository(db_session)
        found = await repo.get_by_id("nonexistent-id")
        assert found is None

    async def test_get_by_path(self, db_session: AsyncSession):
        repo = ProjectRepository(db_session)
        await repo.create(name="test", path="/tmp/my-project")
        found = await repo.get_by_path("/tmp/my-project")
        assert found is not None
        assert found.name == "test"

    async def test_get_or_create_new(self, db_session: AsyncSession):
        repo = ProjectRepository(db_session)
        project, created = await repo.get_or_create(name="new-project", path="/tmp/new")
        assert created is True
        assert project.name == "new-project"

    async def test_get_or_create_existing(self, db_session: AsyncSession):
        repo = ProjectRepository(db_session)
        await repo.create(name="existing", path="/tmp/existing")
        project, created = await repo.get_or_create(name="existing", path="/tmp/existing")
        assert created is False
        assert project.name == "existing"

    async def test_list_all(self, db_session: AsyncSession):
        repo = ProjectRepository(db_session)
        await repo.create(name="project-1", path="/tmp/p1")
        await repo.create(name="project-2", path="/tmp/p2")
        projects = await repo.list_all()
        assert len(projects) == 2


class TestComponentRepository:
    """Tests for ComponentRepository."""

    async def test_save_components(self, db_session: AsyncSession):
        project_repo = ProjectRepository(db_session)
        project = await project_repo.create(name="test", path="/tmp/test")

        comp_repo = ComponentRepository(db_session)
        components = [
            DetectedComponent(
                name="django",
                version="4.2.11",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            ),
            DetectedComponent(
                name="flask",
                version="3.0",
                version_type=VersionType.EXACT,
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            ),
        ]
        db_components = await comp_repo.save_components(project.id, components)
        assert len(db_components) == 2
        assert db_components[0].name == "django"
        assert db_components[1].name == "flask"

    async def test_save_replaces_existing(self, db_session: AsyncSession):
        project_repo = ProjectRepository(db_session)
        project = await project_repo.create(name="test", path="/tmp/test")

        comp_repo = ComponentRepository(db_session)

        # First save
        await comp_repo.save_components(
            project.id,
            [
                DetectedComponent(
                    name="old-package",
                    ecosystem=Ecosystem.PYPI,
                    source_file="requirements.txt",
                )
            ],
        )

        # Second save should replace
        await comp_repo.save_components(
            project.id,
            [
                DetectedComponent(
                    name="new-package",
                    ecosystem=Ecosystem.PYPI,
                    source_file="requirements.txt",
                )
            ],
        )

        found = await comp_repo.get_by_project(project.id)
        assert len(found) == 1
        assert found[0].name == "new-package"


class TestSourceRepository:
    """Tests for SourceRepository."""

    async def test_get_or_create_new(self, db_session: AsyncSession):
        repo = SourceRepository(db_session)
        source, created = await repo.get_or_create(
            name="CISA KEV",
            source_type="kev",
            url="https://example.com",
        )
        assert created is True
        assert source.name == "CISA KEV"

    async def test_get_or_create_existing(self, db_session: AsyncSession):
        repo = SourceRepository(db_session)
        await repo.get_or_create(name="CISA KEV", source_type="kev")
        _source, created = await repo.get_or_create(name="CISA KEV", source_type="kev")
        assert created is False

    async def test_update_sync_status(self, db_session: AsyncSession):
        repo = SourceRepository(db_session)
        source, _ = await repo.get_or_create(name="Test", source_type="test")
        await repo.update_sync_status(
            source.id,
            SourceStatus.ACTIVE,
            record_count=100,
        )
        await db_session.flush()
        found = await repo.get_by_name("Test")
        assert found is not None
        assert found.status == "active"
        assert found.record_count == 100


class TestVulnerabilityRepository:
    """Tests for VulnerabilityRepository."""

    async def test_upsert_vulnerabilities(self, db_session: AsyncSession):
        source_repo = SourceRepository(db_session)
        source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="kev")

        vuln_repo = VulnerabilityRepository(db_session)
        records = [
            VulnerabilityRecord(
                cve_id="CVE-2024-1000",
                source_name="CISA KEV",
                vendor_project="Django",
                product="Django",
            ),
            VulnerabilityRecord(
                cve_id="CVE-2024-2000",
                source_name="CISA KEV",
                vendor_project="Flask",
                product="Flask",
            ),
        ]
        count = await vuln_repo.upsert_vulnerabilities(source.id, records)
        assert count == 2

    async def test_upsert_replaces_existing(self, db_session: AsyncSession):
        source_repo = SourceRepository(db_session)
        source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="kev")

        vuln_repo = VulnerabilityRepository(db_session)

        # First upsert
        await vuln_repo.upsert_vulnerabilities(
            source.id,
            [
                VulnerabilityRecord(
                    cve_id="CVE-OLD",
                    source_name="CISA KEV",
                    vendor_project="Old",
                    product="Old",
                )
            ],
        )

        # Second upsert should replace
        await vuln_repo.upsert_vulnerabilities(
            source.id,
            [
                VulnerabilityRecord(
                    cve_id="CVE-NEW",
                    source_name="CISA KEV",
                    vendor_project="New",
                    product="New",
                )
            ],
        )

        all_vulns = await vuln_repo.get_all_by_source(source.id)
        assert len(all_vulns) == 1
        assert all_vulns[0].cve_id == "CVE-NEW"

    async def test_get_by_cve(self, db_session: AsyncSession):
        source_repo = SourceRepository(db_session)
        source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="kev")

        vuln_repo = VulnerabilityRepository(db_session)
        await vuln_repo.upsert_vulnerabilities(
            source.id,
            [
                VulnerabilityRecord(
                    cve_id="CVE-2024-1234",
                    source_name="CISA KEV",
                    vendor_project="Test",
                    product="Test",
                )
            ],
        )

        results = await vuln_repo.get_by_cve("CVE-2024-1234")
        assert len(results) == 1

    async def test_to_domain(self, db_session: AsyncSession):
        source_repo = SourceRepository(db_session)
        source, _ = await source_repo.get_or_create(name="CISA KEV", source_type="kev")

        vuln_repo = VulnerabilityRepository(db_session)
        await vuln_repo.upsert_vulnerabilities(
            source.id,
            [
                VulnerabilityRecord(
                    cve_id="CVE-2024-1234",
                    source_name="CISA KEV",
                    vendor_project="Django",
                    product="Django",
                    cwes=["CWE-89"],
                )
            ],
        )

        db_vulns = await vuln_repo.get_all()
        domain = vuln_repo.to_domain(db_vulns[0])
        assert domain.cve_id == "CVE-2024-1234"
        assert domain.vendor_project == "Django"
        assert domain.cwes == ["CWE-89"]


class TestScanRepository:
    """Tests for ScanRepository."""

    async def test_create_scan(self, db_session: AsyncSession):
        project_repo = ProjectRepository(db_session)
        project = await project_repo.create(name="test", path="/tmp/test")

        scan_repo = ScanRepository(db_session)
        scan = await scan_repo.create(project.id)
        assert scan.id is not None
        assert scan.status == "running"

    async def test_complete_scan(self, db_session: AsyncSession):
        project_repo = ProjectRepository(db_session)
        project = await project_repo.create(name="test", path="/tmp/test")

        scan_repo = ScanRepository(db_session)
        scan = await scan_repo.create(project.id)
        await scan_repo.complete(
            scan.id,
            components_found=10,
            vulnerabilities_found=5,
            kev_matches=2,
            duration_seconds=1.5,
        )
        await db_session.flush()

        found = await scan_repo.get_by_id(scan.id)
        assert found is not None
        assert found.status == "completed"
        assert found.components_found == 10

    async def test_complete_scan_with_error(self, db_session: AsyncSession):
        project_repo = ProjectRepository(db_session)
        project = await project_repo.create(name="test", path="/tmp/test")

        scan_repo = ScanRepository(db_session)
        scan = await scan_repo.create(project.id)
        await scan_repo.complete(scan.id, error="Something went wrong")
        await db_session.flush()

        found = await scan_repo.get_by_id(scan.id)
        assert found is not None
        assert found.status == "failed"
        assert found.error == "Something went wrong"
