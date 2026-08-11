"""Behavioral wiring tests for the maintainer live-auth matrix."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts import live_auth_matrix


def _args(*, skip_browser: bool) -> argparse.Namespace:
    argv = [
        "--profile",
        "source",
        "--account",
        "maintainer@example.com",
        "--base-url",
        "https://notebooklm.google.com",
        "--timeout",
        "10",
    ]
    if skip_browser:
        argv.append("--skip-browser")
    return live_auth_matrix.parse_args(argv)


def _interactive_args() -> argparse.Namespace:
    return live_auth_matrix.parse_args(
        [
            "--profile",
            "source",
            "--account",
            "maintainer@example.com",
            "--base-url",
            "https://notebooklm.google.com",
            "--timeout",
            "10",
            "--skip-browser",
            "--skip-rest",
            "--skip-mcp",
            "--include-interactive",
            "--cdp-url",
            "http://127.0.0.1:9222",
        ]
    )


def _source_profile(tmp_path: Path) -> Path:
    source = tmp_path / "profiles" / "source"
    source.mkdir(parents=True)
    (source / "storage_state.json").write_text('{"cookies": []}', encoding="utf-8")
    (source / "master_token.json").write_text('{"token": "test-only"}', encoding="utf-8")
    return source


def test_skip_browser_still_runs_storage_and_access_gate_cells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _source_profile(tmp_path)
    monkeypatch.setattr(live_auth_matrix, "DEFAULT_HOME", tmp_path)
    matrix = live_auth_matrix.Matrix(_args(skip_browser=True))
    calls: list[str] = []

    always = (
        "phase_baseline",
        "phase_master_refresh",
        "phase_import_filter",
        "phase_hosts",
        "phase_rpc_bundle_health",
        "phase_rpc_health",
        "phase_concurrency",
        "phase_storage_mid_session",
        "phase_sibling_concurrent_mid_session",
        "phase_master_token_mid_session",
        "phase_rest_auth_recovery",
        "phase_mcp_auth_recovery",
        "phase_rpc_access_gate_contract",
        "phase_fault_injection",
        "phase_crash_safety",
    )
    for name in always:
        monkeypatch.setattr(matrix, name, lambda name=name: calls.append(name))
    monkeypatch.setattr(
        matrix,
        "phase_browser_discovery",
        lambda: pytest.fail("browser discovery must be skipped"),
    )
    monkeypatch.setattr(
        matrix,
        "phase_browser_login",
        lambda: pytest.fail("browser login must be skipped"),
    )
    monkeypatch.setattr(
        matrix,
        "phase_browser_mid_session",
        lambda: pytest.fail("browser refresh must be skipped"),
    )
    monkeypatch.setattr(
        matrix,
        "phase_interactive_playwright_login",
        lambda: pytest.fail("interactive Playwright login must be opt-in"),
    )
    monkeypatch.setattr(
        matrix,
        "phase_interactive_master_token_login",
        lambda: pytest.fail("interactive master-token login must be opt-in"),
    )
    monkeypatch.setattr(
        matrix,
        "phase_interactive_cdp_master_token_login",
        lambda: pytest.fail("interactive CDP login must be opt-in"),
    )
    monkeypatch.setattr(matrix, "revision", lambda: "test-revision")
    monkeypatch.setattr(
        matrix,
        "worktree_info",
        lambda: {"worktree_dirty": False, "worktree_diff_hash": "test"},
    )

    assert matrix.run() == 0
    capsys.readouterr()
    assert calls == list(always)


def test_include_interactive_runs_all_human_cells_and_reports_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _source_profile(tmp_path)
    monkeypatch.setattr(live_auth_matrix, "DEFAULT_HOME", tmp_path)
    matrix = live_auth_matrix.Matrix(_interactive_args())
    calls: list[str] = []
    always = (
        "phase_baseline",
        "phase_master_refresh",
        "phase_import_filter",
        "phase_hosts",
        "phase_rpc_bundle_health",
        "phase_rpc_health",
        "phase_concurrency",
        "phase_storage_mid_session",
        "phase_sibling_concurrent_mid_session",
        "phase_master_token_mid_session",
        "phase_rpc_access_gate_contract",
        "phase_fault_injection",
        "phase_crash_safety",
    )
    for name in always:
        monkeypatch.setattr(matrix, name, lambda: None)
    interactive = (
        "phase_interactive_playwright_login",
        "phase_interactive_master_token_login",
        "phase_interactive_cdp_master_token_login",
    )
    for name in interactive:
        monkeypatch.setattr(matrix, name, lambda name=name: calls.append(name))
    monkeypatch.setattr(matrix, "revision", lambda: "test-revision")
    monkeypatch.setattr(
        matrix,
        "worktree_info",
        lambda: {"worktree_dirty": False, "worktree_diff_hash": "test"},
    )

    assert matrix.run() == 0
    report = json.loads(capsys.readouterr().out)
    assert calls == list(interactive)
    assert report["interactive_cells"] == "executed"
    assert report["interactive_cdp"] == "configured"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:9222",
        "http://user@127.0.0.1:9222",
        "http://127.0.0.1:9222/json/version",
        "http://127.0.0.1:9222?token=secret",
        "ws://127.0.0.1:9222",
        "http://127.0.0.1",
    ],
)
def test_interactive_cdp_rejects_non_loopback_or_non_root_url(url: str) -> None:
    with pytest.raises(SystemExit):
        live_auth_matrix.parse_args(
            [
                "--account",
                "maintainer@example.com",
                "--include-interactive",
                "--cdp-url",
                url,
            ]
        )


@pytest.mark.parametrize(
    "argv",
    [
        ["--account", "maintainer@example.com", "--include-interactive"],
        [
            "--account",
            "maintainer@example.com",
            "--cdp-url",
            "http://127.0.0.1:9222",
        ],
    ],
)
def test_interactive_mode_and_cdp_url_require_each_other(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        live_auth_matrix.parse_args(argv)


def test_interactive_login_cells_use_isolated_profiles_and_verify_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix = live_auth_matrix.Matrix(_interactive_args())
    calls: list[tuple[Path, tuple[str, ...], str | None, int | None]] = []

    def fake_cli(
        home: Path,
        *args: str,
        profile: str | None = None,
        timeout: int | None = None,
        **extra: str,
    ) -> subprocess.CompletedProcess[str]:
        assert not extra
        calls.append((home, args, profile, timeout))
        assert profile is not None
        if args[0] == "login":
            profile_dir = home / "profiles" / profile
            profile_dir.mkdir(parents=True, exist_ok=True)
            (profile_dir / "storage_state.json").write_text('{"cookies": []}', encoding="utf-8")
            if "--master-token" in args:
                (profile_dir / "master_token.json").write_text(
                    '{"master_token": "test-only"}', encoding="utf-8"
                )
            return subprocess.CompletedProcess(list(args), 0, "", "")
        return subprocess.CompletedProcess(list(args), 0, '{"status": "ok"}', "")

    probes: list[str] = []

    def fake_cdp_probe(name: str) -> bool:
        probes.append(name)
        matrix.results.append({"name": name, "status": "pass", "reachable": True})
        return True

    monkeypatch.setattr(matrix, "cli", fake_cli)
    monkeypatch.setattr(matrix, "_record_cdp_endpoint", fake_cdp_probe)
    try:
        matrix.phase_interactive_playwright_login()
        matrix.phase_interactive_master_token_login()
        matrix.phase_interactive_cdp_master_token_login()
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    login_calls = [call for call in calls if call[1][0] == "login"]
    assert [call[2] for call in login_calls] == [
        "interactive-playwright",
        "interactive-master-token",
        "interactive-cdp-master-token",
    ]
    assert all(call[3] == 390 for call in login_calls)
    assert login_calls[0][1] == (
        "login",
        "--browser-timeout",
        "360",
        "--browser",
        "chromium",
    )
    assert all(call[1][1:3] == ("--browser-timeout", "360") for call in login_calls)
    assert "--master-token" in login_calls[1][1]
    assert "--cdp-url" in login_calls[2][1]
    assert login_calls[2][1][-1] == "http://127.0.0.1:9222"
    assert probes == ["interactive-cdp-endpoint-before", "interactive-cdp-endpoint-after"]
    assert [result["name"] for result in matrix.results] == [
        "interactive-playwright-login",
        "interactive-playwright-live-check",
        "interactive-master-token-login",
        "interactive-master-token-live-check",
        "interactive-cdp-endpoint-before",
        "interactive-cdp-master-token-login",
        "interactive-cdp-master-token-live-check",
        "interactive-cdp-endpoint-after",
    ]
    master_results = [
        result
        for result in matrix.results
        if result["name"]
        in {"interactive-master-token-login", "interactive-cdp-master-token-login"}
    ]
    assert all(result["master_token_created"] is True for result in master_results)
    assert all(result["storage_state_created"] is True for result in master_results)


def test_cdp_endpoint_probe_reports_reachability_without_response_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    matrix = live_auth_matrix.Matrix(_interactive_args())
    observed: dict[str, object] = {}

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"Browser": "private-detail"}'

    def fake_urlopen(url: str, *, timeout: int) -> Response:
        observed.update(url=url, timeout=timeout)
        return Response()

    monkeypatch.setattr(live_auth_matrix.urllib.request, "urlopen", fake_urlopen)
    try:
        assert matrix._record_cdp_endpoint("cdp-probe") is True
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    assert observed == {"url": "http://127.0.0.1:9222/json/version", "timeout": 5}
    assert matrix.results == [{"name": "cdp-probe", "status": "pass", "reachable": True}]
    assert "private-detail" not in json.dumps(matrix.results)


def test_storage_mid_session_cell_disables_every_external_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source_profile(tmp_path)
    monkeypatch.setattr(live_auth_matrix, "DEFAULT_HOME", tmp_path)
    matrix = live_auth_matrix.Matrix(_args(skip_browser=True))
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        home: Path,
        *,
        timeout: int | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = matrix.env(home, **(env_overrides or {}))
        if len(command) >= 3 and command[-2] == "-c":
            compile(command[-1], "<live-auth-matrix-cell>", "exec")
        observed["command"] = command
        observed["env"] = env
        observed["timeout"] = timeout
        copied = matrix.temp / "mid-session-storage" / "profiles" / "mid-session-storage"
        assert not (copied / "master_token.json").exists()
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps({"before": 2, "after": 2, "reload_calls": 1, "live_cookies": 8}),
            "",
        )

    monkeypatch.setattr(matrix, "_run", fake_run)
    try:
        matrix.phase_storage_mid_session()
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    env = observed["env"]
    assert isinstance(env, dict)
    assert env["NOTEBOOKLM_REFRESH_BROWSER"] == ""
    assert env["NOTEBOOKLM_REFRESH_CMD"] == ""
    assert env["NOTEBOOKLM_REFRESH_CMD_MIDSESSION"] == ""
    assert env["NOTEBOOKLM_PROFILE"] == "mid-session-storage"
    command = observed["command"]
    assert isinstance(command, list)
    child_script = command[-1]
    assert "try_storage_cookie_reload = tracked_reload" in child_script
    assert "external recovery rung reached" in child_script
    assert "before_ids == after_ids" in child_script
    assert "assert " not in child_script
    assert matrix.results == [
        {
            "name": "mid-session-storage-reload",
            "status": "pass",
            "returncode": 0,
            "json": {"before": 2, "after": 2, "reload_calls": 1, "live_cookies": 8},
        }
    ]


def test_baseline_report_keeps_count_but_not_private_notebook_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source_profile(tmp_path)
    monkeypatch.setattr(live_auth_matrix, "DEFAULT_HOME", tmp_path)
    matrix = live_auth_matrix.Matrix(_args(skip_browser=True))
    responses = iter(
        (
            subprocess.CompletedProcess(["auth"], 0, '{"status": "ok"}', ""),
            subprocess.CompletedProcess(
                ["list"],
                0,
                '{"count": 1, "notebooks": [{"id": "private-id", "title": "Private"}]}',
                "",
            ),
        )
    )
    monkeypatch.setattr(matrix, "cli", lambda *args, **kwargs: next(responses))
    try:
        matrix.phase_baseline()
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    assert matrix.results[1]["json"] == {"count": 1}
    assert "private-id" not in json.dumps(matrix.results)


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (0, '[{"id": "private-id", "title": "Private"}]'),
        (0, '{"notebooks": [{"id": "private-id", "title": "Private"}]}'),
        (0, "not-json-private-id"),
        (1, '{"count": 1, "notebooks": [{"id": "private-id"}]}'),
    ],
)
def test_baseline_report_fails_closed_without_private_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stdout: str,
) -> None:
    _source_profile(tmp_path)
    monkeypatch.setattr(live_auth_matrix, "DEFAULT_HOME", tmp_path)
    matrix = live_auth_matrix.Matrix(_args(skip_browser=True))
    responses = iter(
        (
            subprocess.CompletedProcess(["auth"], 0, '{"status": "ok"}', ""),
            subprocess.CompletedProcess(["list"], returncode, stdout, "list failed"),
        )
    )
    monkeypatch.setattr(matrix, "cli", lambda *args, **kwargs: next(responses))
    try:
        matrix.phase_baseline()
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    result = matrix.results[1]
    assert result["status"] == "fail"
    assert "json" not in result
    assert "private-id" not in json.dumps(result)


def test_realistic_recovery_cells_wire_real_process_and_adapter_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source_profile(tmp_path)
    monkeypatch.setattr(live_auth_matrix, "DEFAULT_HOME", tmp_path)
    matrix = live_auth_matrix.Matrix(_args(skip_browser=True))
    matrix.args.rpc_health_full = True
    matrix.args.read_only_notebook_id = "read-only-id"
    matrix.args.generation_notebook_id = "generation-id"
    calls: list[tuple[list[str], dict[str, str], int | None]] = []

    def fake_run(
        command: list[str],
        home: Path,
        *,
        timeout: int | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = matrix.env(home, **(env_overrides or {}))
        if len(command) >= 3 and command[-2] == "-c":
            compile(command[-1], "<live-auth-matrix-cell>", "exec")
        if env.get("NOTEBOOKLM_PROFILE") == "mid-session-browser":
            browser_profile = (
                matrix.temp / "mid-session-browser" / "profiles" / "mid-session-browser"
            )
            assert not (browser_profile / "master_token.json").exists()
        calls.append((command, env, timeout))
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(matrix, "_run", fake_run)
    try:
        matrix.phase_rpc_health()
        matrix.phase_sibling_concurrent_mid_session()
        matrix.phase_master_token_mid_session()
        matrix.phase_rest_auth_recovery()
        matrix.phase_mcp_auth_recovery()
        matrix.phase_browser_mid_session()
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    by_profile = {
        env["NOTEBOOKLM_PROFILE"]: (command, env, timeout) for command, env, timeout in calls
    }
    assert len(by_profile) == len(calls), "a phase issued more than one subprocess call"

    rpc_command, rpc_env, rpc_timeout = by_profile["rpc-health"]
    assert rpc_command[-1] == "--full"
    assert "check_rpc_health.py" in rpc_command[-2]
    assert rpc_env["NOTEBOOKLM_READ_ONLY_NOTEBOOK_ID"] == "read-only-id"
    assert rpc_env["NOTEBOOKLM_GENERATION_NOTEBOOK_ID"] == "generation-id"
    assert rpc_timeout == 300

    sibling_script = by_profile["mid-session-sibling"][0][-1]
    assert "--master-token-refresh" in sibling_script
    assert "asyncio.gather" in sibling_script
    assert "reload_calls <= 3" in sibling_script
    assert "recovered_ids == [before_ids] * 4" in sibling_script

    master_script = by_profile["mid-session-master"][0][-1]
    assert 'state["cookies"] = []' in master_script
    assert "tracked_master" in master_script
    assert "master_calls == 1" in master_script
    assert "before_ids == after_ids" in master_script

    rest_script = by_profile["rest-live"][0][-1]
    assert 'http.get("/v1/notebooks"' in rest_script
    assert "app.state.notebooklm.client is None" in rest_script
    assert "--master-token-refresh" in rest_script
    assert 'require(token.is_file(), "rest-stale profile has no master_token.json")' in rest_script
    assert "before_ids == after_ids == rebound_ids" in rest_script

    mcp_script = by_profile["mcp-live"][0][-1]
    assert 'mcp.call_tool("notebook_list"' in mcp_script
    assert "keepalive=600.0" in mcp_script
    assert '"total" in before and "notebooks" in before' in mcp_script

    browser_command, browser_env, browser_timeout = by_profile["mid-session-browser"]
    browser_script = browser_command[-1]
    assert 'state["cookies"] = []' in browser_script
    assert "tracked_refresh" in browser_script
    assert "refresh_calls == 1" in browser_script
    assert "before_ids == after_ids" in browser_script
    assert browser_env["NOTEBOOKLM_PROFILE"] == "mid-session-browser"
    assert browser_env["NOTEBOOKLM_HEADLESS_REAUTH"] == ""
    assert browser_timeout == 180

    child_scripts = [
        sibling_script,
        master_script,
        rest_script,
        mcp_script,
        browser_script,
    ]
    assert all("assert " not in script for script in child_scripts)


def test_run_normalizes_launch_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    matrix = live_auth_matrix.Matrix(_args(skip_browser=True))

    def fail_to_launch(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("private path must not be copied")

    monkeypatch.setattr(live_auth_matrix.subprocess, "Popen", fail_to_launch)
    try:
        result = matrix._run(["missing-command"], tmp_path)
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    assert result.returncode == 127
    assert result.stdout == ""
    assert result.stderr == "unable to launch matrix phase: FileNotFoundError"
    assert "private path" not in result.stderr


def test_concurrent_refresh_reaps_started_worker_after_partial_launch_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source_profile(tmp_path)
    monkeypatch.setattr(live_auth_matrix, "DEFAULT_HOME", tmp_path)
    matrix = live_auth_matrix.Matrix(_args(skip_browser=True))

    class StartedProcess:
        pid = 12345
        returncode: int | None = None
        terminated = False
        communicated = False

        def poll(self) -> int | None:
            return self.returncode

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            self.communicated = True
            self.returncode = -9
            return "", ""

    started = StartedProcess()
    launch_calls = 0

    def partial_launch(*args: object, **kwargs: object) -> StartedProcess:
        nonlocal launch_calls
        launch_calls += 1
        if launch_calls == 1:
            return started
        raise OSError("private launch detail")

    def terminate(process: object) -> None:
        assert process is started
        started.terminated = True

    monkeypatch.setattr(live_auth_matrix.subprocess, "Popen", partial_launch)
    monkeypatch.setattr(matrix, "_terminate_process_tree", terminate)
    try:
        matrix.phase_concurrency()
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    assert started.terminated is True
    assert started.communicated is True
    assert matrix.results == [
        {
            "name": "concurrent-refresh",
            "status": "fail",
            "returncodes": [127],
            "error": "unable to launch refresh worker: OSError",
        }
    ]
    assert "private launch detail" not in json.dumps(matrix.results)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group regression")
def test_run_terminates_descendant_processes_on_timeout(tmp_path: Path) -> None:
    matrix = live_auth_matrix.Matrix(_args(skip_browser=True))
    child_pid_path = tmp_path / "child.pid"
    script = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "Path(sys.argv[1]).write_text(str(child.pid), encoding='utf-8')\n"
        "time.sleep(60)\n"
    )
    try:
        result = matrix._run(
            [sys.executable, "-c", script, str(child_pid_path)],
            tmp_path,
            timeout=1,
        )
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        for _ in range(40):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            pytest.fail("timed-out matrix phase left its descendant running")
    finally:
        live_auth_matrix.shutil.rmtree(matrix.temp, ignore_errors=True)

    assert result.returncode == 124
