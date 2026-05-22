"""Utility functions."""

from scqlog.config import Config


def get_version() -> str:
    """Return the application version string.

    Returns:
        Version string from Config.VERSION (e.g., "1.0.0").
    """
    return Config.VERSION
