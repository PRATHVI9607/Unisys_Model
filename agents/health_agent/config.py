"""Configuration management for Health Agent."""

import os
from typing import Dict, Optional
from pydantic import BaseModel, Field, validator


class HealthAgentConfig(BaseModel):
    """Health Agent configuration."""

    # Kubernetes
    namespace: str = Field(
        default_factory=lambda: os.getenv("NAMESPACE", "kubeheal"),
        description="Kubernetes namespace for agent",
    )
    in_cluster: bool = Field(
        default_factory=lambda: os.getenv("IN_CLUSTER", "true").lower() == "true",
        description="Load in-cluster Kubernetes config",
    )

    # Redis
    redis_url: str = Field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://redis-master:6379"),
        description="Redis connection URL",
    )
    redis_timeout: int = Field(
        default=30, description="Redis operation timeout in seconds"
    )

    # DIT-Sec Model Server
    dit_sec_url: str = Field(
        default_factory=lambda: os.getenv("DIT_SEC_URL", "http://dit-sec-server:8000"),
        description="DIT-Sec model server URL",
    )
    dit_sec_timeout: int = Field(
        default=30, description="DIT-Sec request timeout in seconds"
    )
    dit_sec_retries: int = Field(default=3, description="DIT-Sec request retry count")

    # Prometheus
    prometheus_url: str = Field(
        default_factory=lambda: os.getenv("PROMETHEUS_URL", "http://prometheus:9090"),
        description="Prometheus server URL",
    )
    prometheus_timeout: int = Field(
        default=10, description="Prometheus query timeout in seconds"
    )

    # Cooldown
    cooldown_ttl: int = Field(
        default=300, description="Cooldown period in seconds after assessment"
    )

    # Baseline
    baseline_configmap: str = Field(
        default="kubeheal-baselines", description="ConfigMap name for baseline storage"
    )
    baseline_max_age_days: int = Field(
        default=30, description="Maximum age of baseline in days before warning"
    )

    # Watch configuration
    watch_label_selector: str = Field(
        default="kubeheal.io/watch=true",
        description="Label selector for watched deployments",
    )
    watch_all_namespaces: bool = Field(
        default=True, description="Watch all namespaces or specific namespace only"
    )

    # Logging
    log_level: str = Field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"),
        description="Logging level",
    )

    # Assessment
    delay_before_telemetry: int = Field(
        default=15, description="Delay in seconds before fetching telemetry"
    )

    # Data loader
    dataset_path: Optional[str] = Field(
        default=None, description="Path to training dataset (CSV or JSON)"
    )

    @property
    def training_dataset_path(self) -> Optional[str]:
        """Alias for dataset_path for backward compatibility."""
        return self.dataset_path

    @validator("log_level")
    def validate_log_level(cls, v):
        valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        if v.upper() not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v.upper()

    @validator("redis_url", "dit_sec_url", "prometheus_url")
    def validate_urls(cls, v):
        if not v.startswith(("http://", "https://", "redis://")):
            raise ValueError("URLs must start with http://, https://, or redis://")
        return v

    class Config:
        env_file = ".env"
        case_sensitive = False


def load_config() -> HealthAgentConfig:
    """Load configuration from environment."""
    return HealthAgentConfig()
