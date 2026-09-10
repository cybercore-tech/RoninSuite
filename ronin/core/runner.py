"""Run orchestrator: scope-check -> execute -> stream -> parse -> persist -> audit."""
from __future__ import annotations

import datetime as _dt
import subprocess
import threading
from pathlib import Path
from typing import Callable

from ronin.config import paths
from ronin.core import audit, db
from ronin.core.models import Finding, RunStatus, ToolRun, dedupe
from ronin.core.scope import Scope, ScopeViolation
from ronin.tools.base import RunContext, ToolAdapter

LineCB = Callable[[str, str], None]  # (stream, line) -> None ; stream in {"out","err","sys"}


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def run_tool(
    adapter: ToolAdapter,
    engagement: str,
    target: str,
    *,
    options: dict | None = None,
    intensity: str = "normal",
    scope: Scope | None = None,
    force: bool = False,
    force_reason: str = "",
    timeout: int | None = None,
    on_line: LineCB | None = None,
) -> ToolRun:
    """Execute one tool against one target and return the persisted ToolRun.

    Findings are written to the DB; ``ToolRun.result_files`` points at the raw
    evidence.  Out-of-scope targets raise :class:`ScopeViolation` unless
    ``force=True`` (which requires ``force_reason`` and is logged).
    """
    options = {**adapter.option_defaults(), **(options or {})}
    emit = on_line or (lambda *_: None)
    run = ToolRun(engagement=engagement, tool=adapter.name, target=target,
                  forced=force, force_reason=force_reason)

    # --- 1. scope gate -----------------------------------------------------
    if scope is not None:
        decision = scope.check(target)
        audit.record("scope.check", engagement=engagement, tool=adapter.name,
                     target=target, allowed=decision.allowed, rule=decision.matched_rule,
                     reason=decision.reason)
        if not decision.allowed:
            if not force:
                run.status = RunStatus.BLOCKED
                run.error = decision.reason
                run.finished = _now()
                db.upsert_engagement_stub(engagement)
                db.save_run(run)
                raise ScopeViolation(decision)
            if not force_reason.strip():
                raise ValueError("force=True requires a written force_reason")
            emit("sys", f"[FORCED] out of scope: {decision.reason} :: {force_reason}")
            audit.record("scope.override", engagement=engagement, tool=adapter.name,
                         target=target, reason=force_reason)
        elif not decision.within_window:
            emit("sys", f"[WARNING] {decision.reason}")

    # --- 2. build command ------------------------------------------------------
    ev = paths().evidence_dir(engagement, run.id)
    ctx = RunContext(engagement=engagement, target=target, evidence_dir=ev,
                     options=options, intensity=intensity)
    if not adapter.is_installed():
        raise FileNotFoundError(
            f"{adapter.resolved_binary!r} not found on PATH - run `ronin doctor --install {adapter.name}`"
        )
    argv = adapter.build_argv(ctx)
    run.argv = argv
    run.evidence_dir = str(ev)
    (ev / "command.txt").write_text(" ".join(_shq(a) for a in argv) + "\n")

    # --- 3. execute + stream -------------------------------------------------
    run.status = RunStatus.RUNNING
    db.upsert_engagement_stub(engagement)
    db.save_run(run)
    audit.record("run.start", engagement=engagement, run_id=run.id, tool=adapter.name,
                 target=target, argv=argv, forced=force)
    emit("sys", "$ " + " ".join(_shq(a) for a in argv))

    out_f = (ev / "stdout.log").open("w", encoding="utf-8", errors="replace")
    err_f = (ev / "stderr.log").open("w", encoding="utf-8", errors="replace")
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, cwd=ev,
        )
    except OSError as e:
        run.status = RunStatus.ERROR
        run.error = str(e)
        run.finished = _now()
        db.save_run(run)
        audit.record("run.error", run_id=run.id, error=str(e))
        out_f.close(); err_f.close()
        raise

    def _pump(pipe, sink, tag):
        for line in iter(pipe.readline, ""):
            sink.write(line)
            sink.flush()
            emit(tag, line.rstrip("\n"))
        pipe.close()

    threads = [
        threading.Thread(target=_pump, args=(proc.stdout, out_f, "out"), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, err_f, "err"), daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        proc.wait(timeout=timeout or adapter.default_timeout)
        run.status = RunStatus.OK if proc.returncode == 0 else RunStatus.ERROR
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        run.status = RunStatus.TIMEOUT
        emit("sys", "[TIMEOUT] process killed")
    for t in threads:
        t.join(timeout=5)
    out_f.close(); err_f.close()
    run.exit_code = proc.returncode
    run.finished = _now()

    # --- 4. parse + persist ------------------------------------------------
    findings: list[Finding] = []
    if run.status in (RunStatus.OK, RunStatus.ERROR, RunStatus.TIMEOUT):
        try:
            raw = adapter.parse(run, ctx)
            for f in raw:
                f.run_id = run.id
                f.engagement = engagement
            findings = dedupe(raw)
        except Exception as e:  # a parser bug must not lose the run
            run.error = f"parse failed: {e}"
            emit("sys", run.error)

    run.result_files = [str(p) for p in ctx.result_files if Path(p).exists()]
    (ev / "findings.json").write_text(
        "[\n" + ",\n".join(f.model_dump_json(indent=2) for f in findings) + "\n]\n"
    )
    db.save_run(run)
    db.save_findings(findings)
    audit.record("run.finish", run_id=run.id, tool=adapter.name, status=run.status.value,
                 exit_code=run.exit_code, findings=len(findings),
                 duration_s=run.duration_s)
    emit("sys", f"[DONE] status={run.status.value} findings={len(findings)} "
                f"evidence={ev}")
    return run


def _shq(s: str) -> str:
    return s if s and all(c.isalnum() or c in "-_=/.:@,+" for c in s) else "'" + s.replace("'", "'\\''") + "'"
