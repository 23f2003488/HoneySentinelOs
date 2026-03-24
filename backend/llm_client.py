"""
HoneySentinel-OS — Azure OpenAI Client
Single place where the Azure OpenAI connection is configured.
All agents call get_llm_client() — never instantiate AzureOpenAI directly.
"""

from __future__ import annotations

import os
import logging
from typing import Optional
from openai import AzureOpenAI

logger = logging.getLogger(__name__)

_client: Optional[AzureOpenAI] = None


def get_llm_client() -> AzureOpenAI:
    """
    Singleton factory. Reads credentials from environment.
    Call once at startup — subsequent calls return the same client.
    """
    global _client
    if _client is not None:
        return _client

    endpoint   = os.getenv("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
    api_key    = os.getenv("AZURE_OPENAI_API_KEY", "")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")

    if not endpoint or not api_key:
        raise RuntimeError(
            "Missing AZURE_OPENAI_ENDPOINT or AZURE_OPENAI_API_KEY in environment. "
            "Check your .env file."
        )

    _client = AzureOpenAI(
        azure_endpoint=endpoint,
        api_key=api_key,
        api_version=api_version,
    )

    logger.info(f"Azure OpenAI client initialised → {endpoint}")
    return _client


def get_deployment() -> str:
    """Returns the GPT-4o deployment name from env."""
    return os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")


def reset_llm_client() -> None:
    """Reset singleton — for tests."""
    global _client
    _client = None
