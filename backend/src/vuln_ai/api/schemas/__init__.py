"""API schemas package."""

from vuln_ai.api.schemas.ai import AIAnalysisResponse, DecisionResultResponse
from vuln_ai.api.schemas.common import ErrorDetail, ErrorResponse, PaginatedResponse
from vuln_ai.api.schemas.components import ComponentResponse
from vuln_ai.api.schemas.matches import MatchResponse
from vuln_ai.api.schemas.projects import ProjectCreate, ProjectResponse, ProjectUpdate
from vuln_ai.api.schemas.risk import RiskAssessmentResponse
from vuln_ai.api.schemas.scans import ScanCreateRequest, ScanResponse, ScanSummary
from vuln_ai.api.schemas.sources import SourceResponse, SourceSyncResponse
from vuln_ai.api.schemas.vulnerabilities import VulnerabilityResponse

__all__ = [
    "AIAnalysisResponse",
    "ComponentResponse",
    "DecisionResultResponse",
    "ErrorDetail",
    "ErrorResponse",
    "MatchResponse",
    "PaginatedResponse",
    "ProjectCreate",
    "ProjectResponse",
    "ProjectUpdate",
    "RiskAssessmentResponse",
    "ScanCreateRequest",
    "ScanResponse",
    "ScanSummary",
    "SourceResponse",
    "SourceSyncResponse",
    "VulnerabilityResponse",
]
