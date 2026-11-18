"""Shared fixtures. The pg_db fixture starts a throwaway postgres:16-alpine
container with fake credentials, migrates it, and yields an async DSN."""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _cleanup(name: str) -> None:
    # best-effort teardown; --rm container dies with the daemon anyway
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


@pytest.fixture(scope="session")
def pg_db() -> Iterator[str]:
    if shutil.which("docker") is None:
        pytest.skip("docker not available — DB tests need a throwaway postgres")
    try:
        probe = subprocess.run(["docker", "info"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("docker daemon not reachable — DB tests need a throwaway postgres")
    if probe.returncode != 0:
        pytest.skip("docker daemon not reachable — DB tests need a throwaway postgres")
    name = f"custos-test-{uuid.uuid4().hex[:10]}"
    port = _free_port()
    # Obviously fake test credentials only.
    try:
        started = subprocess.run(
            [
                "docker", "run", "-d", "--rm", "--name", name,
                "-e", "POSTGRES_USER=custos",
                "-e", "POSTGRES_PASSWORD=cu-test-password",
                "-e", "POSTGRES_DB=custos",
                "-p", f"127.0.0.1:{port}:5432",
                "postgres:16-alpine",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if started.returncode != 0:
            raise RuntimeError(f"docker run failed: {started.stderr.strip()}")
        sync_dsn = f"postgresql://custos:cu-test-password@127.0.0.1:{port}/custos"
        deadline = time.monotonic() + 60
        while True:
            if time.monotonic() > deadline:
                raise RuntimeError("postgres did not become ready in 60s")
            try:
                ready = subprocess.run(
                    ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "custos"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except subprocess.TimeoutExpired:
                time.sleep(0.5)
                continue
            if ready.returncode == 0:
                break
            gone = subprocess.run(["docker", "inspect", name], capture_output=True, timeout=15)
            if gone.returncode != 0:
                raise RuntimeError("postgres container exited during startup")
            time.sleep(0.5)
        env = {
            **os.environ,
            "CUSTOS_TEST_DSN": sync_dsn,
            "CUSTOS_DATABASE_URL": "",
            "CUSTOS_DATABASE_URL_FILE": "",
        }
        migrated = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if migrated.returncode != 0:
            raise RuntimeError(f"alembic failed: {migrated.stderr.strip()}")
        yield f"postgresql+asyncpg://custos:cu-test-password@127.0.0.1:{port}/custos"
    finally:
        _cleanup(name)
