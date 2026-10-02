"""Application configuration using pydantic-settings."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database configuration."""

    url: str = Field(
        default="sqlite+aiosqlite:///./vuln_ai.db",
        description="SQLAlchemy database URL",
    )
    echo: bool = Field(default=False, description="Echo SQL statements")


class KEVSourceSettings(BaseSettings):
    """CISA KEV source configuration."""

    url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="CISA KEV JSON feed URL",
    )
    mirror_url: str = Field(
        default="https://cisagov.github.io/kev-data/jsonFiles/knownExploitedVulnerabilities.json",
        description="CISA KEV GitHub mirror URL (fallback)",
    )
    timeout_seconds: int = Field(default=30, description="HTTP request timeout")
    user_agent: str = Field(
        default="local-vulnerability-ai/0.1.0",
        description="User-Agent header for HTTP requests",
    )
    max_retries: int = Field(default=3, description="Maximum retry attempts")


class ScannerSettings(BaseSettings):
    """Scanner configuration."""

    max_components: int = Field(
        default=10000,
        description="Maximum number of components to detect per project",
    )


class OllamaSettings(BaseSettings):
    """Ollama LLM provider configuration."""

    enabled: bool = Field(default=True, description="Enable Ollama LLM provider")
    base_url: str = Field(default="http://localhost:11434", description="Ollama API base URL")
    model: str = Field(default="llama3.2", description="Ollama LLM model name")
    temperature: float = Field(default=0.0, description="Sampling temperature")
    timeout_seconds: int = Field(default=60, description="Ollama request timeout in seconds")


class DecisionSettings(BaseSettings):
    """SystemOne decision provider configuration."""

    enabled: bool = Field(default=True, description="Enable decision model provider")
    base_url: str = Field(default="http://localhost:11434", description="SystemOne endpoint host")
    model: str = Field(
        default="tev1:4b",
        description="Decision model identifier (e.g. nimble, tev1:4b, tev1:0.8b)",
    )
    timeout_seconds: int = Field(default=30, description="Decision request timeout in seconds")


class AISettings(BaseSettings):
    """Overall AI layer configuration."""

    enabled: bool = Field(default=True, description="Global switch to enable/disable AI analysis")
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    decision: DecisionSettings = Field(default_factory=DecisionSettings)


class APISettings(BaseSettings):
    """FastAPI configuration."""

    host: str = Field(default="127.0.0.1", description="API server host")
    port: int = Field(default=8000, description="API server port")
    cors_origins: list[str] = Field(
        default=[
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ],
        description="Allowed CORS origins",
    )
    title: str = Field(default="Local Vulnerability AI API", description="API title")
    version: str = Field(default="0.1.0", description="API version")


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_prefix="VULN_AI_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    data_dir: Path = Field(
        default=Path.home() / ".local" / "share" / "vuln-ai",
        description="Directory for application data (database, cache)",
    )
    log_level: str = Field(default="INFO", description="Logging level")

    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    kev: KEVSourceSettings = Field(default_factory=KEVSourceSettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    ai: AISettings = Field(default_factory=AISettings)
    api: APISettings = Field(default_factory=APISettings)

    def get_db_url(self) -> str:
        """Get the database URL, resolving relative paths against data_dir."""
        url = self.database.url
        if url.startswith("sqlite") and ":///" in url:
            # For relative sqlite paths, resolve against data_dir
            db_path = url.split(":///", 1)[1]
            if not Path(db_path).is_absolute():
                self.data_dir.mkdir(parents=True, exist_ok=True)
                resolved = self.data_dir / db_path
                return f"sqlite+aiosqlite:///{resolved}"
        return url


def get_settings() -> Settings:
    """Create and return application settings."""
    return Settings()
