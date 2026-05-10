#!/usr/bin/env python3
"""Health Agent Entrypoint for KubeHeal v3.0.

This module initializes and runs the Health Agent as a Kubernetes-native service
for detecting configuration drift and assessing deployment health.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path

try:
    from config import HealthAgentConfig
    from agent import HealthAgent
    from training_pipeline import TrainingPipeline
except ImportError:
    from agents.health_agent.config import HealthAgentConfig
    from agents.health_agent.agent import HealthAgent
    from agents.health_agent.training_pipeline import TrainingPipeline

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class HealthAgentService:
    """Manages Health Agent service lifecycle."""

    def __init__(self, config: HealthAgentConfig):
        """Initialize service with configuration.

        Args:
            config: HealthAgentConfig instance
        """
        self.config = config
        self.agent: HealthAgent | None = None
        self.running = False

    async def initialize(self) -> None:
        """Initialize the Health Agent."""
        logger.info("Initializing Health Agent...")

        try:
            # Create agent instance
            self.agent = HealthAgent(
                namespace=self.config.namespace,
                redis_url=self.config.redis_url,
                dit_sec_url=self.config.dit_sec_url,
                prometheus_url=self.config.prometheus_url,
            )

            logger.info(
                f"Health Agent initialized for namespace: {self.config.namespace}"
            )

            # Optionally load and process training dataset
            if self.config.dataset_path:
                await self._load_training_dataset()

        except Exception as e:
            logger.error(f"Failed to initialize Health Agent: {e}", exc_info=True)
            raise

    async def _load_training_dataset(self) -> None:
        """Load and process training dataset if provided.

        This prepares telemetry data for model training and validation.
        """
        dataset_path = self.config.training_dataset_path

        if not dataset_path or not Path(dataset_path).exists():
            logger.warning(f"Training dataset not found: {dataset_path}")
            return

        try:
            logger.info(f"Loading training dataset from {dataset_path}...")
            pipeline = TrainingPipeline(dataset_path)
            processed_data, stats = pipeline.run()

            logger.info(
                f"Processed {stats['total_samples']} training samples with "
                f"{stats['n_features']} features"
            )
            logger.info(
                f"Severity distribution: {stats.get('severity_distribution', {})}"
            )
            logger.info(f"Label distribution: {stats.get('label_distribution', {})}")

            # TODO: Store processed data and statistics for model training
            # This would integrate with a model training service

        except Exception as e:
            logger.error(f"Failed to load training dataset: {e}", exc_info=True)
            # Continue without training data - not a fatal error

    async def run(self) -> None:
        """Run the Health Agent service.

        Note: The agent currently demonstrates initialization and dataset loading.
        Full event watching requires kubernetes-asyncio or another async K8s client.
        """
        if not self.agent:
            raise RuntimeError("Agent not initialized")

        logger.info("Starting Health Agent service...")
        self.running = True

        try:
            # The agent is ready to watch deployments
            # In production, this would call: await self.agent.watch_deployments()
            # For now, keep the service running to demonstrate readiness
            logger.info("Health Agent is ready to process deployment events")
            logger.info("(Actual event watching requires kubernetes-asyncio)")

            # Keep service running - in production this would be the event loop
            while self.running:
                await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("Health Agent service cancelled")
        except Exception as e:
            logger.error(f"Health Agent service error: {e}", exc_info=True)
            raise
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Gracefully shutdown the service."""
        logger.info("Shutting down Health Agent service...")
        self.running = False

        if self.agent:
            try:
                await self.agent.stop()
                logger.info("Health Agent stopped")
            except Exception as e:
                logger.error(f"Error stopping Health Agent: {e}")


async def main() -> int:
    """Main entry point for Health Agent service.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    logger.info("=" * 70)
    logger.info("KubeHeal v3.0 - Health Agent Service")
    logger.info("=" * 70)

    try:
        # Load configuration from environment
        config = HealthAgentConfig()
        logger.info(f"Configuration loaded: namespace={config.namespace}")

        # Create and initialize service
        service = HealthAgentService(config)
        await service.initialize()

        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_event_loop()

        def signal_handler(sig):
            logger.info(f"Received signal {sig}, initiating shutdown...")
            loop.create_task(service.shutdown())

        loop.add_signal_handler(signal.SIGTERM, signal_handler, signal.SIGTERM)
        loop.add_signal_handler(signal.SIGINT, signal_handler, signal.SIGINT)

        # Run service
        await service.run()

        logger.info("Health Agent service stopped successfully")
        return 0

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(1)
