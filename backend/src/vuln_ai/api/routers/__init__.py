"""Routers package."""

from vuln_ai.api.routers.ai import router as ai_router
from vuln_ai.api.routers.components import router as components_router
from vuln_ai.api.routers.health import router as health_router
from vuln_ai.api.routers.images import router as images_router
from vuln_ai.api.routers.matches import router as matches_router
from vuln_ai.api.routers.policies import router as policies_router
from vuln_ai.api.routers.projects import router as projects_router
from vuln_ai.api.routers.scans import router as scans_router
from vuln_ai.api.routers.sources import router as sources_router
from vuln_ai.api.routers.suppressions import router as suppressions_router
from vuln_ai.api.routers.vulnerabilities import router as vulnerabilities_router

__all__ = [
    "ai_router",
    "components_router",
    "health_router",
    "images_router",
    "matches_router",
    "policies_router",
    "projects_router",
    "scans_router",
    "sources_router",
    "suppressions_router",
    "vulnerabilities_router",
]
