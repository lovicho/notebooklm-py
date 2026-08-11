#!/usr/bin/env python3
r"""Repeatable live authentication matrix for maintainer/release validation.

This runner deliberately uses disposable ``NOTEBOOKLM_HOME`` directories for
every write.  It never logs cookie or token values.  The source profile and
browser profile are read-only inputs.

Example::

    uv run --extra browser --extra cookies --extra headless --extra mcp --extra server \
      python scripts/live_auth_matrix.py \
      --profile source-profile \
      --browser 'chromium::Profile 3' \
      --account maintainer@example.com \
      --base-url https://notebooklm.google.com \
      --output live-matrix.json

Opt-in human-interaction cells (start a loopback CDP browser first)::

    DISPLAY=:10 google-chrome \
      --remote-debugging-port=9222 \
      --remote-debugging-address=127.0.0.1 \
      --user-data-dir=/tmp/notebooklm-live-cdp
    DISPLAY=:10 uv run --extra browser --extra cookies --extra headless --extra mcp --extra server \
      python scripts/live_auth_matrix.py \
      --profile source-profile \
      --browser 'chromium::Profile 3' \
      --account maintainer@example.com \
      --include-interactive \
      --cdp-url http://127.0.0.1:9222

The JSON report is suitable for attaching to a release checklist. All writes
go to a disposable ``NOTEBOOKLM_HOME`` and the temporary credential copies are
removed when the run finishes. Covered cells include baseline/live token
checks, browser-cookie login, master-token re-mint, cookie import filtering,
both NotebookLM hosts, live RPC and frontend-bundle health, concurrent refresh,
strict storage-only mid-session recovery (#2161), a real sibling-process re-mint
followed by simultaneous failing RPCs, actual mid-session master-token fallback,
optional browser-backed mid-session recovery, access-gate classification
(#2175), transient-fault recovery (503, connection failure, and read timeout),
and crash-safe canonical writes.

The browser cookie extractor is host-sensitive: use the host where the browser
profile currently has its NotebookLM binding. Generic human-interaction coverage
is available with ``--include-interactive``: ordinary headed Playwright login,
initial headed master-token bootstrap, and master-token capture through an
operator-owned loopback CDP browser. Those cells are off by default and require
``--cdp-url`` plus a visible desktop (for example ``DISPLAY=:10`` on X11). The
matrix never closes the operator-owned CDP browser and verifies that its endpoint
survives the attached login. Workspace/SSO, regional-account, long-duration
expiry, and remote MCP HTTP/bearer/file-side-channel checks remain account- or
deployment-specific manual cells. The matrix's MCP auth-recovery cell uses
FastMCP's real in-memory protocol transport; deployed file-route coverage is
available from ``scripts/mcp_live_smoke.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HOME = Path(os.environ.get("NOTEBOOKLM_HOME", Path.home() / ".notebooklm"))


def _timeout_text(value: str | bytes | None) -> str:
    """Normalize ``TimeoutExpired`` output despite subprocess stub variance."""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


def _loopback_cdp_url(value: str) -> str:
    """Validate the HTTP root of an operator-owned loopback CDP browser."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("CDP URL is malformed") from exc
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None or port is None:
        raise argparse.ArgumentTypeError(
            "CDP URL must be an explicit http(s) loopback endpoint with a port"
        )
    if parsed.username is not None or parsed.password is not None:
        raise argparse.ArgumentTypeError("CDP URL must not contain credentials")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise argparse.ArgumentTypeError("CDP URL must be a credential-free endpoint root")
    host = parsed.hostname.casefold()
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"
    if not is_loopback:
        raise argparse.ArgumentTypeError("CDP URL must use localhost or a loopback IP address")
    return value


def _positive_int(value: str) -> int:
    """Parse a strictly positive timeout for an interactive cell."""
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return parsed


class Matrix:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.results: list[dict[str, Any]] = []
        self.temp = Path(tempfile.mkdtemp(prefix="notebooklm-live-matrix-"))
        self.base_env = os.environ.copy()
        self.base_env.update(
            {
                "PYTHONPATH": str(ROOT / "src"),
                "NOTEBOOKLM_BASE_URL": args.base_url,
                "NOTEBOOKLM_REFRESH_BROWSER": args.browser,
            }
        )
        self.base_env.pop("NOTEBOOKLM_AUTH_JSON", None)

    def env(self, home: Path, **extra: str) -> dict[str, str]:
        env = self.base_env.copy()
        env["NOTEBOOKLM_HOME"] = str(home)
        env.update(extra)
        return env

    def _run(
        self,
        command: list[str],
        home: Path,
        *,
        timeout: int | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run one isolated matrix subprocess with consistent timeout reporting."""
        effective_timeout = self.args.timeout if timeout is None else timeout
        try:
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                env=self.env(home, **(env_overrides or {})),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **self._process_group_options(),
            )
        except OSError as exc:
            return subprocess.CompletedProcess(
                command,
                127,
                "",
                f"unable to launch matrix phase: {type(exc).__name__}",
            )

        try:
            stdout, stderr = process.communicate(timeout=effective_timeout)
        except subprocess.TimeoutExpired as exc:
            self._terminate_process_tree(process)
            stdout, _stderr = process.communicate()
            return subprocess.CompletedProcess(
                command,
                124,
                stdout or _timeout_text(exc.stdout),
                f"timed out after {effective_timeout}s",
            )
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    @staticmethod
    def _process_group_options() -> dict[str, Any]:
        """Return platform-specific options for isolating a phase process tree."""
        if os.name == "nt":
            return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
        return {"start_new_session": True}

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
        """Terminate a timed-out phase and every child that inherited its credentials."""
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()

    def cli(
        self,
        home: Path,
        *args: str,
        profile: str | None = None,
        timeout: int | None = None,
        **extra: str,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-m", "notebooklm.notebooklm_cli"]
        if profile:
            command.extend(["--profile", profile])
        command.extend(args)
        return self._run(command, home, timeout=timeout, env_overrides=extra)

    def record(
        self,
        name: str,
        proc: subprocess.CompletedProcess[str],
        *,
        expect_json: bool = False,
        include_stdout_on_failure: bool = False,
    ) -> None:
        payload: dict[str, Any] = {
            "name": name,
            "status": "pass" if proc.returncode == 0 else "fail",
            "returncode": proc.returncode,
        }
        if expect_json:
            try:
                payload["json"] = json.loads(proc.stdout)
            except json.JSONDecodeError:
                payload["json_error"] = proc.stdout[-1000:]
                payload["status"] = "fail"
        if proc.returncode != 0:
            payload["stderr"] = proc.stderr[-2000:]
            if include_stdout_on_failure:
                payload["stdout_tail"] = proc.stdout[-4000:]
        self.results.append(payload)

    def copy_profile(self, source: str, home: Path, target: str) -> None:
        source_dir = DEFAULT_HOME / "profiles" / source
        target_dir = home / "profiles" / target
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_dir, target_dir)

    def run(self) -> int:
        try:
            source_dir = DEFAULT_HOME / "profiles" / self.args.profile
            storage_path = source_dir / "storage_state.json"
            if not source_dir.is_dir() or not storage_path.is_file():
                self.results.append(
                    {
                        "name": "profile-input",
                        "status": "fail",
                        "error": f"profile or storage missing: {source_dir}",
                    }
                )
                return 1
            self.phase_baseline()
            if not self.args.skip_browser:
                self.phase_browser_discovery()
                self.phase_browser_login()
            self.phase_master_refresh()
            self.phase_import_filter()
            self.phase_hosts()
            self.phase_rpc_bundle_health()
            self.phase_rpc_health()
            self.phase_concurrency()
            self.phase_storage_mid_session()
            self.phase_sibling_concurrent_mid_session()
            self.phase_master_token_mid_session()
            if not self.args.skip_rest:
                self.phase_rest_auth_recovery()
            if not self.args.skip_mcp:
                self.phase_mcp_auth_recovery()
            if not self.args.skip_browser:
                self.phase_browser_mid_session()
            self.phase_rpc_access_gate_contract()
            self.phase_fault_injection()
            self.phase_crash_safety()
            if self.args.include_interactive:
                self.phase_interactive_playwright_login()
                self.phase_interactive_master_token_login()
                self.phase_interactive_cdp_master_token_login()
        finally:
            try:
                report = {
                    "revision": self.revision(),
                    "profile": self.args.profile,
                    "account": self.args.account,
                    "browser": self.args.browser,
                    "base_url": self.args.base_url,
                    "browser_cells": "skipped" if self.args.skip_browser else "executed",
                    "rest_cells": "skipped" if self.args.skip_rest else "executed",
                    "mcp_cells": "skipped" if self.args.skip_mcp else "executed",
                    "interactive_cells": (
                        "executed" if self.args.include_interactive else "skipped"
                    ),
                    "interactive_cdp": "configured" if self.args.cdp_url else "not-configured",
                    "rpc_health_mode": "full" if self.args.rpc_health_full else "quick",
                    **self.worktree_info(),
                    "results": self.results,
                    "temporary_home": str(self.temp),
                }
                output = json.dumps(report, indent=2, sort_keys=True)
                if self.args.output:
                    self.args.output.write_text(output + "\n", encoding="utf-8")
                print(output)
            finally:
                # Always remove the disposable home — it holds copied live
                # credentials, so a failure serializing/writing/printing the
                # report must never leave them on disk.
                shutil.rmtree(self.temp, ignore_errors=True)
        return 0 if all(item["status"] == "pass" for item in self.results) else 1

    def worktree_info(self) -> dict[str, Any]:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        ).stdout
        diff = subprocess.run(
            ["git", "diff", "HEAD"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        ).stdout
        return {
            "worktree_dirty": bool(status),
            "worktree_diff_hash": hashlib.sha256(diff.encode()).hexdigest(),
        }

    def revision(self) -> str:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=False
        )
        return proc.stdout.strip()

    def phase_baseline(self) -> None:
        home = self.temp / "baseline"
        self.copy_profile(self.args.profile, home, "baseline")
        proc = self.cli(
            home,
            "auth",
            "check",
            "--test",
            "--passive",
            "--json",
            profile="baseline",
        )
        self.record("baseline-auth", proc, expect_json=True)
        proc = self.cli(home, "--quiet", "list", "--json", profile="baseline")
        self.record("baseline-list", proc, expect_json=True)
        # The report is meant for release-checklist attachment. A notebook
        # inventory contains private titles and stable ids; the cell needs only
        # the count to prove the RPC succeeded.
        result = self.results[-1]
        payload = result.pop("json", None)
        result.pop("json_error", None)
        count = payload.get("count") if isinstance(payload, dict) else None
        if proc.returncode == 0 and type(count) is int and count >= 0:
            result["json"] = {"count": count}
        elif proc.returncode == 0:
            result["status"] = "fail"
            result["json_error"] = "baseline response has no non-negative integer count"

    def phase_browser_discovery(self) -> None:
        proc = self.cli(DEFAULT_HOME, "auth", "inspect", "--browser", self.args.browser, "--json")
        self.record("browser-account-discovery", proc, expect_json=True)

    def phase_browser_login(self) -> None:
        home = self.temp / "browser"
        proc = self.cli(
            home,
            "login",
            "--browser-cookies",
            self.args.browser,
            "--account",
            self.args.account,
            "--profile-name",
            "browser-test",
        )
        self.record("browser-cookie-login", proc)
        proc = self.cli(
            home, "auth", "check", "--test", "--passive", "--json", profile="browser-test"
        )
        self.record("browser-cookie-live-check", proc, expect_json=True)

    def _interactive_login(
        self,
        *,
        home_name: str,
        profile: str,
        result_prefix: str,
        login_args: tuple[str, ...],
        require_master_token: bool,
    ) -> None:
        """Run one human login in isolation and verify its credential artifacts live."""
        home = self.temp / home_name
        proc = self.cli(
            home,
            "login",
            "--browser-timeout",
            str(self.args.interactive_timeout),
            *login_args,
            profile=profile,
            timeout=self.args.interactive_timeout + 30,
        )
        self.record(f"{result_prefix}-login", proc)
        profile_dir = home / "profiles" / profile
        result = self.results[-1]
        storage_exists = (profile_dir / "storage_state.json").is_file()
        result["storage_state_created"] = storage_exists
        required_artifacts_exist = storage_exists
        if require_master_token:
            master_exists = (profile_dir / "master_token.json").is_file()
            result["master_token_created"] = master_exists
            required_artifacts_exist = required_artifacts_exist and master_exists
        if proc.returncode == 0 and not required_artifacts_exist:
            result["status"] = "fail"
            result["error"] = "successful login did not create required credential files"
        if result["status"] != "pass":
            return
        proc = self.cli(
            home,
            "auth",
            "check",
            "--test",
            "--passive",
            "--json",
            profile=profile,
            timeout=self.args.timeout,
        )
        self.record(f"{result_prefix}-live-check", proc, expect_json=True)

    def phase_interactive_playwright_login(self) -> None:
        """Exercise ordinary headed Playwright login and its saved live session."""
        print(
            "Interactive cell 1/3: complete ordinary login in the headed browser.",
            file=sys.stderr,
            flush=True,
        )
        self._interactive_login(
            home_name="interactive-playwright",
            profile="interactive-playwright",
            result_prefix="interactive-playwright",
            login_args=("--browser", self.args.interactive_browser),
            require_master_token=False,
        )

    def phase_interactive_master_token_login(self) -> None:
        """Exercise initial master-token bootstrap through a headed browser."""
        print(
            "Interactive cell 2/3: complete the headed master-token bootstrap.",
            file=sys.stderr,
            flush=True,
        )
        self._interactive_login(
            home_name="interactive-master-token",
            profile="interactive-master-token",
            result_prefix="interactive-master-token",
            login_args=(
                "--master-token",
                "--account",
                self.args.account,
                "--browser",
                self.args.interactive_browser,
            ),
            require_master_token=True,
        )

    def _record_cdp_endpoint(self, name: str) -> bool:
        """Record whether the validated local CDP browser remains reachable."""
        endpoint = f"{self.args.cdp_url.rstrip('/')}/json/version"
        try:
            with urllib.request.urlopen(endpoint, timeout=5) as response:
                payload = json.loads(response.read())
                reachable = response.status == 200 and isinstance(payload, dict)
        except Exception as exc:  # noqa: BLE001 - report only the value-free exception type
            self.results.append(
                {
                    "name": name,
                    "status": "fail",
                    "error": f"CDP endpoint probe raised {type(exc).__name__}",
                }
            )
            return False
        self.results.append(
            {
                "name": name,
                "status": "pass" if reachable else "fail",
                "reachable": reachable,
            }
        )
        return reachable

    def phase_interactive_cdp_master_token_login(self) -> None:
        """Exercise master-token capture through an operator-owned CDP browser."""
        print(
            "Interactive cell 3/3: complete EmbeddedSetup in the CDP browser.",
            file=sys.stderr,
            flush=True,
        )
        if not self._record_cdp_endpoint("interactive-cdp-endpoint-before"):
            return
        self._interactive_login(
            home_name="interactive-cdp-master-token",
            profile="interactive-cdp-master-token",
            result_prefix="interactive-cdp-master-token",
            login_args=(
                "--master-token",
                "--account",
                self.args.account,
                "--cdp-url",
                self.args.cdp_url,
            ),
            require_master_token=True,
        )
        self._record_cdp_endpoint("interactive-cdp-endpoint-after")

    def phase_master_refresh(self) -> None:
        home = self.temp / "master"
        self.copy_profile(self.args.profile, home, "master-test")
        proc = self.cli(home, "login", "--master-token-refresh", profile="master-test")
        self.record("master-token-refresh", proc)
        proc = self.cli(
            home, "auth", "check", "--test", "--passive", "--json", profile="master-test"
        )
        self.record("master-token-live-check", proc, expect_json=True)

    def phase_import_filter(self) -> None:
        home = self.temp / "import"
        home.mkdir(parents=True)
        source = DEFAULT_HOME / "profiles" / self.args.profile / "storage_state.json"
        input_path = home / "input.json"
        data = json.loads(source.read_text(encoding="utf-8"))
        data.setdefault("cookies", []).append(
            {
                "name": "MATRIX_SYNTHETIC_YOUTUBE",
                "value": "x",
                "domain": ".youtube.com",
                "path": "/",
            }
        )
        input_path.write_text(json.dumps(data), encoding="utf-8")
        storage = home / "storage_state.json"
        proc = self.cli(
            home, "--storage", str(storage), "auth", "import-cookies", str(input_path), "--json"
        )
        self.record("cookie-import-filter", proc, expect_json=True)
        if proc.returncode == 0:
            stored = json.loads(storage.read_text(encoding="utf-8"))
            ok = not any("youtube.com" in c.get("domain", "") for c in stored.get("cookies", []))
            self.results[-1]["filter_passed"] = ok
            if not ok:
                self.results[-1]["status"] = "fail"

    def phase_hosts(self) -> None:
        home = self.temp / "hosts"
        self.copy_profile(self.args.profile, home, "host-test")
        for host in ("https://notebook.google.com", "https://notebooklm.google.com"):
            proc = self.cli(
                home,
                "auth",
                "check",
                "--test",
                "--passive",
                "--json",
                profile="host-test",
                NOTEBOOKLM_BASE_URL=host,
            )
            self.record(f"host-{host.removeprefix('https://')}", proc, expect_json=True)

    def phase_concurrency(self) -> None:
        home = self.temp / "concurrency"
        self.copy_profile(self.args.profile, home, "shared")
        command = [
            sys.executable,
            "-m",
            "notebooklm.notebooklm_cli",
            "--profile",
            "shared",
            "auth",
            "refresh",
            "--verify",
            "--json",
        ]
        processes: list[subprocess.Popen[str]] = []
        statuses: list[int] = []
        stderrs: list[str] = []
        launch_error: str | None = None
        try:
            for _ in range(4):
                try:
                    processes.append(
                        subprocess.Popen(
                            command,
                            cwd=ROOT,
                            env=self.env(home),
                            text=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE,
                            **self._process_group_options(),
                        )
                    )
                except OSError as exc:
                    launch_error = type(exc).__name__
                    break

            if launch_error is None:
                for proc in processes:
                    try:
                        _out, err = proc.communicate(timeout=self.args.timeout)
                        statuses.append(proc.returncode)
                    except subprocess.TimeoutExpired:
                        self._terminate_process_tree(proc)
                        _out, err = proc.communicate()
                        statuses.append(-1)
                    stderrs.append(err or "")
        finally:
            for proc in processes:
                if proc.poll() is None:
                    self._terminate_process_tree(proc)
                    proc.communicate()

        if launch_error is not None:
            self.results.append(
                {
                    "name": "concurrent-refresh",
                    "status": "fail",
                    "returncodes": [127],
                    "error": f"unable to launch refresh worker: {launch_error}",
                }
            )
            return
        entry: dict[str, Any] = {
            "name": "concurrent-refresh",
            "status": "pass" if statuses == [0] * 4 else "fail",
            "returncodes": statuses,
        }
        if entry["status"] == "fail":
            # Honor the report contract: attach bounded stderr tails for the
            # cells that failed. The CLI logs cookie names/diagnostics only,
            # never values, so a 2000-char tail carries no credential material.
            entry["stderr_tails"] = [
                err[-2000:] for status, err in zip(statuses, stderrs, strict=True) if status != 0
            ]
        self.results.append(entry)
        check_proc = self.cli(
            home, "auth", "check", "--test", "--passive", "--json", profile="shared"
        )
        self.record("concurrent-refresh-final-check", check_proc, expect_json=True)

    def phase_rpc_bundle_health(self) -> None:
        """Exercise the authenticated bundle path and its typed exit codes live."""
        home = self.temp / "rpc-bundle"
        self.copy_profile(self.args.profile, home, "rpc-bundle")
        command = [
            sys.executable,
            str(ROOT / "scripts" / "capture_rpc_registry.py"),
            "--check",
            "--check-enums",
        ]
        proc = self._run(
            command,
            home,
            timeout=max(self.args.timeout, 120),
            env_overrides={"NOTEBOOKLM_PROFILE": "rpc-bundle"},
        )
        self.record("rpc-bundle-health", proc, include_stdout_on_failure=True)

    def phase_rpc_health(self) -> None:
        """Run the real RPC canary, using configured stable notebooks when available."""
        home = self.temp / "rpc-health"
        self.copy_profile(self.args.profile, home, "rpc-health")
        command = [sys.executable, str(ROOT / "scripts" / "check_rpc_health.py")]
        if self.args.rpc_health_full:
            command.append("--full")
        extra = {"NOTEBOOKLM_PROFILE": "rpc-health"}
        if self.args.read_only_notebook_id:
            extra["NOTEBOOKLM_READ_ONLY_NOTEBOOK_ID"] = self.args.read_only_notebook_id
        if self.args.generation_notebook_id:
            extra["NOTEBOOKLM_GENERATION_NOTEBOOK_ID"] = self.args.generation_notebook_id
        timeout_floor = 300 if self.args.rpc_health_full else 120
        proc = self._run(
            command,
            home,
            timeout=max(self.args.timeout, timeout_floor),
            env_overrides=extra,
        )
        self.record(
            "rpc-health-full" if self.args.rpc_health_full else "rpc-health-quick",
            proc,
            include_stdout_on_failure=True,
        )

    def phase_storage_mid_session(self) -> None:
        """Prove #2161 recovery uses storage, without another rung masking it."""
        home = self.temp / "mid-session-storage"
        self.copy_profile(self.args.profile, home, "mid-session-storage")
        (home / "profiles" / "mid-session-storage" / "master_token.json").unlink(missing_ok=True)
        script = (
            "import asyncio, json\n"
            "from notebooklm import NotebookLMClient\n"
            "from notebooklm._auth import session as auth_session\n"
            "def require(condition, message):\n"
            "    if not condition:\n"
            "        raise RuntimeError(message)\n"
            "async def main():\n"
            "    reload_calls = 0\n"
            "    original_reload = getattr(auth_session, 'try_storage_cookie_reload', None)\n"
            "    async def tracked_reload(*args, **kwargs):\n"
            "        nonlocal reload_calls\n"
            "        reload_calls += 1\n"
            "        require(original_reload is not None, 'storage reload helper unavailable')\n"
            "        return await original_reload(*args, **kwargs)\n"
            "    async def forbidden(*args, **kwargs):\n"
            "        raise AssertionError('external recovery rung reached')\n"
            "    if original_reload is not None:\n"
            "        auth_session.try_storage_cookie_reload = tracked_reload\n"
            "    auth_session._try_refresh_cmd_reauth = forbidden\n"
            "    auth_session._try_headless_reauth = forbidden\n"
            "    auth_session._try_master_token_reauth = forbidden\n"
            "    async with NotebookLMClient.from_storage(profile='mid-session-storage') as c:\n"
            "        before = await c.notebooks.list()\n"
            "        before_ids = tuple(sorted(item.id for item in before))\n"
            "        live = c._collaborators.kernel.get_http_client().cookies\n"
            "        live.clear()\n"
            "        after = await c.notebooks.list()\n"
            "        after_ids = tuple(sorted(item.id for item in after))\n"
            "        require(reload_calls > 0, 'storage reload rung was not exercised')\n"
            "        require(len(live) > 0, 'storage reload did not restore the live jar')\n"
            "        require(before_ids == after_ids, 'notebook identity changed after recovery')\n"
            "        print(json.dumps({'before': len(before), 'after': len(after), "
            "'reload_calls': reload_calls, 'live_cookies': len(live)}))\n"
            "asyncio.run(main())\n"
        )
        command = [sys.executable, "-c", script]
        proc = self._run(
            command,
            home,
            env_overrides={
                "NOTEBOOKLM_PROFILE": "mid-session-storage",
                "NOTEBOOKLM_REFRESH_BROWSER": "",
                "NOTEBOOKLM_REFRESH_CMD": "",
                "NOTEBOOKLM_REFRESH_CMD_MIDSESSION": "",
            },
        )
        self.record("mid-session-storage-reload", proc, expect_json=True)

    def phase_sibling_concurrent_mid_session(self) -> None:
        """Consume a real sibling re-mint through one concurrent recovery wave."""
        home = self.temp / "mid-session-sibling"
        self.copy_profile(self.args.profile, home, "mid-session-sibling")
        script = textwrap.dedent(
            """\
            import asyncio
            import hashlib
            import json
            import os
            import subprocess
            import sys
            from pathlib import Path

            from notebooklm import NotebookLMClient
            from notebooklm._auth import session as auth_session

            def require(condition, message):
                if not condition:
                    raise RuntimeError(message)

            async def main():
                reload_calls = 0
                original_reload = auth_session.try_storage_cookie_reload

                async def tracked_reload(*args, **kwargs):
                    nonlocal reload_calls
                    reload_calls += 1
                    return await original_reload(*args, **kwargs)

                async def forbidden(*args, **kwargs):
                    raise AssertionError("external recovery rung reached")

                auth_session.try_storage_cookie_reload = tracked_reload
                auth_session._try_refresh_cmd_reauth = forbidden
                auth_session._try_headless_reauth = forbidden
                auth_session._try_master_token_reauth = forbidden
                profile_dir = Path(os.environ["NOTEBOOKLM_HOME"]) / "profiles" / "mid-session-sibling"
                storage = profile_dir / "storage_state.json"
                before_hash = hashlib.sha256(storage.read_bytes()).hexdigest()

                async with NotebookLMClient.from_storage(profile="mid-session-sibling") as client:
                    before = await client.notebooks.list()
                    before_ids = tuple(sorted(item.id for item in before))
                    sibling = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "notebooklm.notebooklm_cli",
                            "--profile",
                            "mid-session-sibling",
                            "login",
                            "--master-token-refresh",
                        ],
                        env=os.environ.copy(),
                        text=True,
                        capture_output=True,
                        timeout=90,
                        check=False,
                    )
                    require(sibling.returncode == 0, sibling.stderr[-1000:])
                    after_hash = hashlib.sha256(storage.read_bytes()).hexdigest()
                    require(
                        after_hash != before_hash,
                        "sibling re-mint did not replace profile state",
                    )
                    (profile_dir / "master_token.json").unlink()
                    live = client._collaborators.kernel.get_http_client().cookies
                    live.clear()
                    recovered = await asyncio.gather(*(client.notebooks.list() for _ in range(4)))
                    counts = [len(items) for items in recovered]
                    recovered_ids = [
                        tuple(sorted(item.id for item in items)) for items in recovered
                    ]
                    require(
                        recovered_ids == [before_ids] * 4,
                        "notebook identity changed after sibling recovery",
                    )
                    require(
                        0 < reload_calls <= 3,
                        "concurrent RPCs did not share one recovery wave",
                    )
                    require(len(live) > 0, "sibling recovery did not restore the live jar")
                    print(json.dumps({
                        "before": len(before),
                        "after": counts,
                        "reload_calls": reload_calls,
                        "live_cookies": len(live),
                        "sibling_profile_changed": True,
                    }))

            asyncio.run(main())
            """
        )
        command = [sys.executable, "-c", script]
        proc = self._run(
            command,
            home,
            timeout=max(self.args.timeout, 120),
            env_overrides={
                "NOTEBOOKLM_PROFILE": "mid-session-sibling",
                "NOTEBOOKLM_REFRESH_BROWSER": "",
                "NOTEBOOKLM_REFRESH_CMD": "",
                "NOTEBOOKLM_REFRESH_CMD_MIDSESSION": "",
                "NOTEBOOKLM_HEADLESS_REAUTH": "",
            },
        )
        self.record("mid-session-sibling-concurrent-reload", proc, expect_json=True)

    def phase_master_token_mid_session(self) -> None:
        """Force the real Layer-4 rung after both live and disk cookies become unusable."""
        home = self.temp / "mid-session-master"
        self.copy_profile(self.args.profile, home, "mid-session-master")
        script = textwrap.dedent(
            """\
            import asyncio
            import json
            import os
            from pathlib import Path

            from notebooklm import NotebookLMClient
            from notebooklm._auth import session as auth_session

            def require(condition, message):
                if not condition:
                    raise RuntimeError(message)

            async def main():
                master_calls = 0
                original_master = auth_session._try_master_token_reauth

                async def tracked_master(*args, **kwargs):
                    nonlocal master_calls
                    master_calls += 1
                    return await original_master(*args, **kwargs)

                auth_session._try_master_token_reauth = tracked_master
                profile_dir = Path(os.environ["NOTEBOOKLM_HOME"]) / "profiles" / "mid-session-master"
                storage = profile_dir / "storage_state.json"

                async with NotebookLMClient.from_storage(profile="mid-session-master") as client:
                    before = await client.notebooks.list()
                    before_ids = tuple(sorted(item.id for item in before))
                    state = json.loads(storage.read_text(encoding="utf-8"))
                    state["cookies"] = []
                    replacement = storage.with_suffix(".matrix-tmp")
                    replacement.write_text(json.dumps(state), encoding="utf-8")
                    os.replace(replacement, storage)
                    live = client._collaborators.kernel.get_http_client().cookies
                    live.clear()
                    after = await client.notebooks.list()
                    after_ids = tuple(sorted(item.id for item in after))
                    persisted = json.loads(storage.read_text(encoding="utf-8"))
                    require(
                        before_ids == after_ids,
                        "notebook identity changed after master-token recovery",
                    )
                    require(
                        master_calls == 1,
                        "mid-session Layer-4 recovery was not exercised once",
                    )
                    require(
                        persisted.get("cookies"),
                        "master-token recovery did not repair storage",
                    )
                    require(len(live) > 0, "master-token recovery did not restore live jar")
                    print(json.dumps({
                        "before": len(before),
                        "after": len(after),
                        "master_token_calls": master_calls,
                        "persisted_cookies": len(persisted["cookies"]),
                        "live_cookies": len(live),
                    }))

            asyncio.run(main())
            """
        )
        command = [sys.executable, "-c", script]
        proc = self._run(
            command,
            home,
            timeout=max(self.args.timeout, 120),
            env_overrides={
                "NOTEBOOKLM_PROFILE": "mid-session-master",
                "NOTEBOOKLM_REFRESH_BROWSER": "",
                "NOTEBOOKLM_REFRESH_CMD": "",
                "NOTEBOOKLM_REFRESH_CMD_MIDSESSION": "",
                "NOTEBOOKLM_HEADLESS_REAUTH": "",
            },
        )
        self.record("mid-session-master-token-recovery", proc, expect_json=True)

    def phase_rest_auth_recovery(self) -> None:
        """Drive REST through live-jar recovery and degraded-startup lazy binding."""
        home = self.temp / "rest-auth"
        self.copy_profile(self.args.profile, home, "rest-live")
        self.copy_profile(self.args.profile, home, "rest-stale")
        (home / "profiles" / "rest-live" / "master_token.json").unlink(missing_ok=True)
        script = textwrap.dedent(
            """\
            import asyncio
            import contextlib
            import json
            import os
            import subprocess
            import sys
            from pathlib import Path

            import httpx

            from notebooklm import NotebookLMClient
            from notebooklm.server.app import create_app

            TOKEN = "matrix-rest-token"
            HEADERS = {"Authorization": f"Bearer {TOKEN}", "Host": "127.0.0.1"}

            def require(condition, message):
                if not condition:
                    raise RuntimeError(message)

            def notebook_ids(response):
                return tuple(sorted(item["id"] for item in response.json()["notebooks"]))

            async def mid_session():
                holder = {}

                @contextlib.asynccontextmanager
                async def factory():
                    async with NotebookLMClient.from_storage(
                        profile="rest-live", keepalive=600.0
                    ) as client:
                        holder["client"] = client
                        yield client

                app = create_app(profile="rest-live", client_factory=factory)
                async with app.router.lifespan_context(app):
                    transport = httpx.ASGITransport(
                        app=app, client=("127.0.0.1", 5555), raise_app_exceptions=False
                    )
                    async with httpx.AsyncClient(
                        transport=transport, base_url="http://127.0.0.1"
                    ) as http:
                        before = await http.get("/v1/notebooks", headers=HEADERS)
                        require(before.status_code == 200, before.text[-1000:])
                        holder["client"]._collaborators.kernel.get_http_client().cookies.clear()
                        after = await http.get("/v1/notebooks", headers=HEADERS)
                        require(after.status_code == 200, after.text[-1000:])
                        return notebook_ids(before), notebook_ids(after)

            async def stale_startup():
                profile_dir = Path(os.environ["NOTEBOOKLM_HOME"]) / "profiles" / "rest-stale"
                storage = profile_dir / "storage_state.json"
                token = profile_dir / "master_token.json"
                held_token = profile_dir / "master_token.matrix-held"
                state = json.loads(storage.read_text(encoding="utf-8"))
                state["cookies"] = []
                replacement = storage.with_suffix(".matrix-tmp")
                replacement.write_text(json.dumps(state), encoding="utf-8")
                os.replace(replacement, storage)
                require(token.is_file(), "rest-stale profile has no master_token.json")
                token.replace(held_token)

                app = create_app(profile="rest-stale")
                async with app.router.lifespan_context(app):
                    require(
                        app.state.notebooklm.client is None,
                        "REST server did not enter degraded startup",
                    )
                    held_token.replace(token)
                    sibling = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "notebooklm.notebooklm_cli",
                            "--profile",
                            "rest-stale",
                            "login",
                            "--master-token-refresh",
                        ],
                        env=os.environ.copy(),
                        text=True,
                        capture_output=True,
                        timeout=90,
                        check=False,
                    )
                    require(sibling.returncode == 0, sibling.stderr[-1000:])
                    transport = httpx.ASGITransport(
                        app=app, client=("127.0.0.1", 5555), raise_app_exceptions=False
                    )
                    async with httpx.AsyncClient(
                        transport=transport, base_url="http://127.0.0.1"
                    ) as http:
                        response = await http.get("/v1/notebooks", headers=HEADERS)
                    require(response.status_code == 200, response.text[-1000:])
                    require(
                        app.state.notebooklm.client is not None,
                        "REST server did not bind a recovered client",
                    )
                    return notebook_ids(response)

            async def main():
                before_ids, after_ids = await mid_session()
                rebound_ids = await stale_startup()
                require(
                    before_ids == after_ids == rebound_ids,
                    "REST recovery changed notebook identity",
                )
                print(json.dumps({
                    "before": len(before_ids),
                    "after_live_reload": len(after_ids),
                    "after_stale_startup_rebind": len(rebound_ids),
                    "stale_startup_rebound": True,
                }))

            asyncio.run(main())
            """
        )
        command = [sys.executable, "-c", script]
        proc = self._run(
            command,
            home,
            timeout=max(self.args.timeout, 150),
            env_overrides={
                "NOTEBOOKLM_PROFILE": "rest-live",
                "NOTEBOOKLM_SERVER_TOKEN": "matrix-rest-token",
                "NOTEBOOKLM_REFRESH_BROWSER": "",
                "NOTEBOOKLM_REFRESH_CMD": "",
                "NOTEBOOKLM_REFRESH_CMD_MIDSESSION": "",
                "NOTEBOOKLM_HEADLESS_REAUTH": "",
            },
        )
        self.record("rest-auth-recovery", proc, expect_json=True)

    def phase_mcp_auth_recovery(self) -> None:
        """Drive a real FastMCP tool call across a live-jar invalidation."""
        home = self.temp / "mcp-auth"
        self.copy_profile(self.args.profile, home, "mcp-live")
        (home / "profiles" / "mcp-live" / "master_token.json").unlink(missing_ok=True)
        script = textwrap.dedent(
            """\
            import asyncio
            import contextlib
            import json

            from fastmcp import Client

            from notebooklm import NotebookLMClient
            from notebooklm.mcp.server import create_server

            def require(condition, message):
                if not condition:
                    raise RuntimeError(message)

            async def main():
                holder = {}

                @contextlib.asynccontextmanager
                async def factory():
                    async with NotebookLMClient.from_storage(
                        profile="mcp-live", keepalive=600.0
                    ) as client:
                        holder["client"] = client
                        yield client

                server = create_server(profile="mcp-live", client_factory=factory)
                async with Client(server) as mcp:
                    before_result = await mcp.call_tool("notebook_list", {"limit": 50})
                    require(
                        before_result.structured_content is not None,
                        "MCP baseline returned no structured content",
                    )
                    before = before_result.structured_content
                    require(
                        "total" in before and "notebooks" in before,
                        "MCP baseline response is incomplete",
                    )
                    holder["client"]._collaborators.kernel.get_http_client().cookies.clear()
                    after_result = await mcp.call_tool("notebook_list", {"limit": 50})
                    require(
                        after_result.structured_content is not None,
                        "MCP recovery returned no structured content",
                    )
                    after = after_result.structured_content
                    require(
                        "total" in after and "notebooks" in after,
                        "MCP recovery response is incomplete",
                    )
                    require(
                        before.get("total") == after.get("total"),
                        "MCP recovery changed the notebook count",
                    )
                    require(
                        before.get("notebooks") == after.get("notebooks"),
                        "MCP recovery changed notebook identity",
                    )
                    live = holder["client"]._collaborators.kernel.get_http_client().cookies
                    require(len(live) > 0, "MCP recovery did not restore the live jar")
                    print(json.dumps({
                        "before": before.get("total"),
                        "after": after.get("total"),
                        "live_cookies": len(live),
                        "transport": "fastmcp-in-memory",
                    }))

            asyncio.run(main())
            """
        )
        command = [sys.executable, "-c", script]
        proc = self._run(
            command,
            home,
            timeout=max(self.args.timeout, 120),
            env_overrides={
                "NOTEBOOKLM_PROFILE": "mcp-live",
                "NOTEBOOKLM_REFRESH_BROWSER": "",
                "NOTEBOOKLM_REFRESH_CMD": "",
                "NOTEBOOKLM_REFRESH_CMD_MIDSESSION": "",
                "NOTEBOOKLM_HEADLESS_REAUTH": "",
            },
        )
        self.record("mcp-auth-recovery", proc, expect_json=True)

    def phase_browser_mid_session(self) -> None:
        home = self.temp / "mid-session-browser"
        self.copy_profile(self.args.profile, home, "mid-session-browser")
        profile_dir = home / "profiles" / "mid-session-browser"
        (profile_dir / "master_token.json").unlink(missing_ok=True)
        script = textwrap.dedent(
            """\
            import asyncio
            import json
            import os
            from pathlib import Path

            from notebooklm import NotebookLMClient
            from notebooklm._auth import session as auth_session

            def require(condition, message):
                if not condition:
                    raise RuntimeError(message)

            async def main():
                refresh_calls = 0
                original_refresh = auth_session._try_refresh_cmd_reauth

                async def tracked_refresh(*args, **kwargs):
                    nonlocal refresh_calls
                    refresh_calls += 1
                    return await original_refresh(*args, **kwargs)

                auth_session._try_refresh_cmd_reauth = tracked_refresh
                profile_dir = Path(os.environ["NOTEBOOKLM_HOME"]) / "profiles" / "mid-session-browser"
                storage = profile_dir / "storage_state.json"

                async with NotebookLMClient.from_storage(profile="mid-session-browser") as client:
                    before = await client.notebooks.list()
                    before_ids = tuple(sorted(item.id for item in before))
                    state = json.loads(storage.read_text(encoding="utf-8"))
                    state["cookies"] = []
                    replacement = storage.with_suffix(".matrix-tmp")
                    replacement.write_text(json.dumps(state), encoding="utf-8")
                    os.replace(replacement, storage)
                    live = client._collaborators.kernel.get_http_client().cookies
                    live.clear()
                    after = await client.notebooks.list()
                    after_ids = tuple(sorted(item.id for item in after))
                    require(
                        before_ids == after_ids,
                        "notebook identity changed after browser recovery",
                    )
                    require(
                        refresh_calls == 1,
                        "browser refresh command rung was not exercised once",
                    )
                    require(len(live) > 0, "browser recovery did not restore live jar")
                    print(json.dumps({
                        "before": len(before),
                        "after": len(after),
                        "refresh_command_calls": refresh_calls,
                        "live_cookies": len(live),
                    }))

            asyncio.run(main())
            """
        )
        command = [sys.executable, "-c", script]
        proc = self._run(
            command,
            home,
            timeout=max(self.args.timeout, 180),
            env_overrides={
                "NOTEBOOKLM_PROFILE": "mid-session-browser",
                "NOTEBOOKLM_REFRESH_CMD": (
                    f"{shlex.quote(sys.executable)} "
                    f"{shlex.quote(str(ROOT / 'examples' / 'refresh_browser_cookies.py'))}"
                ),
                "NOTEBOOKLM_REFRESH_CMD_MIDSESSION": "1",
                "NOTEBOOKLM_HEADLESS_REAUTH": "",
            },
        )
        self.record("mid-session-browser-refresh", proc, expect_json=True)

    def phase_rpc_access_gate_contract(self) -> None:
        """Run the deterministic #2175 classifier and workflow-routing regressions."""
        home = self.temp / "rpc-access-gate"
        home.mkdir(parents=True, exist_ok=True)
        command = [
            "uv",
            "run",
            "pytest",
            "-q",
            "tests/unit/test_scripts_auth_cookie_domains.py::test_capture_rpc_registry_classifies_access_gate_as_auth_failure",
            "tests/unit/test_capture_rpc_registry.py::test_main_reports_bundle_auth_failure_without_drift",
            "tests/unit/test_rpc_health_bundle_lane.py",
        ]
        proc = self._run(command, home)
        self.record("rpc-access-gate-classification", proc)

    def phase_crash_safety(self) -> None:
        home = self.temp / "crash"
        home.mkdir(parents=True)
        source = DEFAULT_HOME / "profiles" / self.args.profile / "storage_state.json"
        expected = json.loads(source.read_text(encoding="utf-8"))
        expected_names = {
            cookie.get("name") for cookie in expected.get("cookies", []) if cookie.get("name")
        }
        required_names = {"SID", "APISID", "SAPISID", "LSID"}
        target = home / "storage_state.json"
        shutil.copy2(source, target)
        script = (
            "import json, sys\n"
            "from pathlib import Path\n"
            "from notebooklm._auth.storage import replace_from_login\n"
            "p=Path(sys.argv[1]); state=json.loads(Path(sys.argv[2]).read_text())\n"
            "[replace_from_login(p, state, include_domains=None) for _ in range(10000)]\n"
        )
        passed = True
        for _ in range(3):
            proc = subprocess.Popen(
                [sys.executable, "-c", script, str(target), str(source)],
                cwd=ROOT,
                env=self.env(home),
            )
            time.sleep(0.08)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            proc.wait(timeout=self.args.timeout)
            try:
                state = json.loads(target.read_text(encoding="utf-8"))
                names = {
                    cookie.get("name") for cookie in state.get("cookies", []) if cookie.get("name")
                }
                passed = passed and required_names.issubset(names & expected_names)
            except json.JSONDecodeError:
                passed = False
        self.results.append(
            {
                "name": "crash-safe-storage-write",
                "status": "pass" if passed else "fail",
                "iterations": 3,
            }
        )

    def phase_fault_injection(self) -> None:
        # Isolate NOTEBOOKLM_HOME even for the pytest cell: base_env leaves it
        # unset, so a test that writes profile state could otherwise touch the
        # caller's real home, breaking the disposable-home guarantee.
        home = self.temp / "fault-injection"
        home.mkdir(parents=True, exist_ok=True)
        command = [
            "uv",
            "run",
            "pytest",
            "-q",
            "tests/unit/test_error_injection_middleware.py",
            "tests/unit/test_retry_middleware.py",
            "tests/unit/test_auth_refresh_middleware.py",
        ]
        proc = self._run(command, home)
        self.record("transient-fault-injection-tests", proc)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", default=os.environ.get("NOTEBOOKLM_PROFILE", "default"))
    parser.add_argument("--account", required=True)
    parser.add_argument("--browser", default="chromium::Profile 3")
    parser.add_argument("--base-url", default="https://notebook.google.com")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--include-interactive",
        action="store_true",
        help=(
            "Run ordinary headed Playwright login, headed master-token bootstrap, and "
            "CDP-attached master-token bootstrap. Off by default; requires --cdp-url."
        ),
    )
    parser.add_argument(
        "--interactive-browser",
        choices=("chromium", "chrome", "msedge"),
        default="chromium",
        help="Browser channel for the two locally launched interactive cells.",
    )
    parser.add_argument(
        "--interactive-timeout",
        type=_positive_int,
        default=360,
        help=(
            "Per-login human interaction timeout in seconds (default: 360); "
            "the child process gets 30 additional seconds for teardown."
        ),
    )
    parser.add_argument(
        "--cdp-url",
        type=_loopback_cdp_url,
        help=(
            "Operator-owned loopback CDP HTTP root for the interactive attach cell, "
            "for example http://127.0.0.1:9222."
        ),
    )
    parser.add_argument(
        "--rpc-health-full",
        action="store_true",
        help="Run the mutating full RPC canary (creates and deletes a temporary notebook).",
    )
    parser.add_argument(
        "--read-only-notebook-id",
        default=os.environ.get("NOTEBOOKLM_READ_ONLY_NOTEBOOK_ID"),
        help="Stable notebook used by the RPC health canary's read-only methods.",
    )
    parser.add_argument(
        "--generation-notebook-id",
        default=os.environ.get("NOTEBOOKLM_GENERATION_NOTEBOOK_ID"),
        help="Stable notebook used by the RPC health canary's generation methods.",
    )
    parser.add_argument(
        "--skip-rest",
        action="store_true",
        help="Skip REST adapter recovery cells when the server extra is unavailable.",
    )
    parser.add_argument(
        "--skip-mcp",
        action="store_true",
        help="Skip MCP adapter recovery cells when the mcp extra is unavailable.",
    )
    parser.add_argument(
        "--skip-browser",
        action="store_true",
        help=(
            "Skip rookiepy browser discovery/login and browser-refresh cells. "
            "Storage-only mid-session recovery and RPC access-gate cells still run."
        ),
    )
    args = parser.parse_args(argv)
    if args.include_interactive and args.cdp_url is None:
        parser.error("--include-interactive requires --cdp-url")
    if args.cdp_url is not None and not args.include_interactive:
        parser.error("--cdp-url requires --include-interactive")
    return args


if __name__ == "__main__":
    raise SystemExit(Matrix(parse_args()).run())
