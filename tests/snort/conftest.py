"""
tests/snort/conftest.py

Configurazione pytest condivisa per i test Snort.
Verifica che lo stack Docker sia in esecuzione prima di avviare i test.
"""

import subprocess
import pytest


REQUIRED_CONTAINERS = [
    "ztaleaks_firewall",
    "ztaleaks_envoy",
    "ztaleaks_snort_internal",
    "ztaleaks_snort_mid",
    "ztaleaks_security_orchestrator",
]


def _is_container_running(name: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", name],
        capture_output=True, text=True
    )
    return result.stdout.strip() == "true"


def pytest_configure(config):
    """Verifica prerequisiti prima di qualsiasi test."""
    missing = [c for c in REQUIRED_CONTAINERS if not _is_container_running(c)]
    if missing:
        pytest.exit(
            f"\n[snort-tests] Stack non avviato. Container mancanti o fermi:\n"
            + "\n".join(f"  - {c}" for c in missing)
            + "\n\nAvvia lo stack con:\n"
            "  docker compose -f deployments/docker/docker-compose.yaml up -d\n",
            returncode=1
        )
