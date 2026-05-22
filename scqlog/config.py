"""Application configuration.

Centralizes all configuration settings, loaded from environment variables
with sensible defaults.
"""

import os


class Config:
    """Application configuration loaded from environment variables.

    All configuration values can be overridden via environment variables.

    Attributes:
        APP_NAME: Application name, from APP_NAME env var (default: "scqlog").
        VERSION: Application version string.
        DEBUG: Enable debug logging, from DEBUG env var (default: False).
        CRS_PARANOIA_LEVEL: OWASP CRS paranoia level 1-4 (default: 1).
            Higher levels detect more attacks but increase false positives.
    """

    # Application info
    APP_NAME = os.getenv("APP_NAME", "scqlog")
    VERSION = "1.0.0"

    # Runtime settings
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    # OWASP CRS paranoia level (1=low false positives, 4=maximum detection)
    CRS_PARANOIA_LEVEL = int(os.getenv("CRS_PARANOIA_LEVEL", "1"))
