"""Custom exceptions for Health Agent."""


class HealthAgentException(Exception):
    """Base exception for Health Agent."""

    pass


class BaselineError(HealthAgentException):
    """Error related to baseline management."""

    pass


class BaselineNotFoundError(BaselineError):
    """Baseline configuration not found."""

    pass


class BaselineValidationError(BaselineError):
    """Baseline validation failed."""

    pass


class K8sAPIError(HealthAgentException):
    """Error communicating with Kubernetes API."""

    pass


class RedisError(HealthAgentException):
    """Error communicating with Redis."""

    pass


class DitSecError(HealthAgentException):
    """Error communicating with DIT-Sec model server."""

    pass


class DitSecTimeoutError(DitSecError):
    """DIT-Sec model server timeout."""

    pass


class SpecDiffError(HealthAgentException):
    """Error during spec diff calculation."""

    pass


class TelemetryError(HealthAgentException):
    """Error fetching telemetry data."""

    pass


class DataLoaderError(HealthAgentException):
    """Error loading training dataset."""

    pass


class ConfigurationError(HealthAgentException):
    """Invalid configuration."""

    pass
