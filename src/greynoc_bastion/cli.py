"""GreyNOC Bastion command-line interface.

A single, namespaced CLI (``bastion``) built on the standard library so there
is no extra dependency and no console-script collision with the source repos.

    bastion status
    bastion doctor
    bastion forecast demo --pretty
    bastion forecast ingest --fixture <path>
    bastion identities scan <path> --out <folder>
    bastion detections validate --scenario <path>
    bastion detections validate --all
    bastion playbooks list
    bastion playbooks show <name>
    bastion assets scan-local --passive
    bastion report build --out <folder>
    bastion serve --host 127.0.0.1 --port 8788
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .app import BastionApp
from .config import load_config
from .schemas import ReportFormat


# --- small output helpers ----------------------------------------------------
def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def _sev_marker(sev: str) -> str:
    return {
        "critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
        "low": "[LOW ]", "info": "[INFO]",
    }.get(sev, "[    ]")


def _app(args) -> BastionApp:
    overrides = {}
    if getattr(args, "host", None):
        overrides["BASTION_HOST"] = args.host
    if getattr(args, "port", None):
        overrides["BASTION_PORT"] = str(args.port)
    config = load_config(overrides=overrides or None)
    return BastionApp(config)


# --- command handlers --------------------------------------------------------
def cmd_status(args) -> int:
    app = _app(args)
    status = app.status()
    if args.json:
        _print_json(status)
        return 0
    c = status["config"]
    print(f"GreyNOC Bastion {status['version']}  —  posture: {status['safety_posture'].upper()}")
    print(f"  API binding      : {c['host']}:{c['port']}  (loopback_only={c['loopback_only']})")
    print(f"  Live fetch       : {c['live_fetch']}")
    print(f"  Active checks    : {c['active_checks']}")
    print(f"  AI assistant     : {c['ai_assistant']} (cmd exec: {c['ai_command_execution']})")
    print(f"  Report dir       : {c['report_dir']}")
    print(f"  Database         : {c['db_path']}")
    print(f"  Playbooks        : {status['playbooks_available']}")
    print("  Stored records   :")
    for k, v in status["counts"].items():
        print(f"      {k:20} {v}")
    return 0


def cmd_doctor(args) -> int:
    app = _app(args)
    result = app.doctor()
    if args.json:
        _print_json(result)
        return 0 if result["ok"] else 1
    print("bastion doctor")
    for c in result["checks"]:
        mark = "  ok  " if c["ok"] else " FAIL "
        print(f"[{mark}] {c['name']:32} {c['detail']}")
    print(f"\nResult: {result['result'].upper()}")
    return 0 if result["ok"] else 1


def cmd_forecast(args) -> int:
    app = _app(args)
    sectors = [s.strip() for s in (args.sectors or "").split(",") if s.strip()] or None
    if args.forecast_cmd == "demo":
        threats = app.threat_forecast.demo(sectors=sectors, persist=args.persist)
    elif args.forecast_cmd == "ingest":
        url = getattr(args, "url", None)
        if url:
            # Guarded live fetch (off by default). Refuses unless live fetching
            # is enabled; HTTPS-only, allowlisted, SSRF-blocked, size/time-capped.
            try:
                threats = app.threat_forecast.ingest_url(url, sectors=sectors, persist=True)
            except Exception as exc:  # noqa: BLE001 - surface a clear operator message
                print(f"error: live fetch refused or failed: {exc}", file=sys.stderr)
                return 2
        elif args.fixture:
            threats = app.threat_forecast.ingest(Path(args.fixture), sectors=sectors, persist=True)
        else:
            print("error: 'forecast ingest' needs --fixture <path> or --url <https-url>",
                  file=sys.stderr)
            return 2
    else:
        print("error: unknown forecast subcommand", file=sys.stderr)
        return 2

    if args.json:
        _print_json([t.to_dict() for t in threats])
        return 0
    print(f"Threat Forecast — {len(threats)} threats ranked by urgency\n")
    for t in threats:
        print(f"{_sev_marker(t.severity.value)} {t.score.urgency:.3f}  {t.threat_id}  {t.title[:70]}")
        if args.pretty:
            for d in t.metadata.get("drivers", []):
                print(f"           - {d}")
            print(f"           remediation: {t.remediation[:90]}")
    return 0


def cmd_identities(args) -> int:
    app = _app(args)
    if args.identities_cmd != "scan":
        print("error: unknown identities subcommand", file=sys.stderr)
        return 2
    target = Path(args.path)
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2
    identities = app.identity.scan(target, persist=True)
    findings = app.identity.to_findings(identities)

    if args.out:
        report = _report_from_findings(app, findings, title=f"Identity Blast Radius — {target}",
                                       modules=["identity"], out_dir=Path(args.out))
        print(f"Report written to {args.out} ({', '.join(report.output_paths)})")

    if args.json:
        _print_json([i.to_dict() for i in identities])
        return 0
    print(f"Identity Blast Radius — {len(identities)} non-human identities (secrets masked)\n")
    for i in identities:
        loc = f"{i.location}:{i.line}" if i.line else i.location
        print(f"{_sev_marker(i.severity.value)} {i.identity_type.value:16} {i.provider or '-':10} "
              f"{i.masked_preview or '(no value)':30} {loc}")
    return 0


def cmd_detections(args) -> int:
    app = _app(args)
    if args.detections_cmd != "validate":
        print("error: unknown detections subcommand", file=sys.stderr)
        return 2
    if args.scenario:
        result = app.detection.validate_scenario(Path(args.scenario), persist=True)
        results = [result]
    else:
        results = app.detection.validate_all(persist=True)

    if args.json:
        _print_json([r.to_dict() for r in results])
        return 0 if all(r.passed for r in results) else 1

    print(f"Detection Validation — {len(results)} result(s)\n")
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        print(f"[{mark}] {r.detection_id:16} verdict={r.verdict.value:12} "
              f"tp={r.true_positives} fp={r.false_positives} fn={r.false_negatives}")
        if args.pretty:
            print(f"         {r.notes}")
    passed = sum(1 for r in results if r.passed)
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


def cmd_playbooks(args) -> int:
    app = _app(args)
    if args.playbooks_cmd == "list":
        pbs = app.list_playbooks()
        if args.json:
            _print_json([{"slug": p.slug, "name": p.name, "category": p.category,
                          "severity": p.severity.value, "techniques": p.attack_techniques}
                         for p in pbs])
            return 0
        print(f"Operator Playbooks — {len(pbs)} available\n")
        for p in sorted(pbs, key=lambda x: (x.category, x.slug)):
            print(f"  {p.slug:36} {p.category:22} [{p.severity.value}]  {p.name[:40]}")
        return 0
    if args.playbooks_cmd == "show":
        pb = app.get_playbook(args.name)
        if not pb:
            print(f"error: playbook not found: {args.name}", file=sys.stderr)
            return 2
        if args.json:
            _print_json(pb.to_dict())
            return 0
        print(f"# {pb.name}  ({pb.slug})")
        print(f"Category: {pb.category} | Severity: {pb.severity.value}")
        print(f"MITRE: {', '.join(pb.attack_techniques) or '—'}")
        if pb.summary:
            print(f"\n{pb.summary}\n")
        if pb.response_steps:
            print("Response checklist:")
            for s in pb.response_steps:
                print(f"  [{s.order:2}] {s.detail}")
        if pb.related_detections:
            print(f"\nRelated draft detections: {', '.join(pb.related_detections)}")
        return 0
    print("error: unknown playbooks subcommand", file=sys.stderr)
    return 2


def cmd_assets(args) -> int:
    app = _app(args)
    if args.assets_cmd != "scan-local":
        print("error: unknown assets subcommand", file=sys.stderr)
        return 2

    want_active = getattr(args, "active", False)
    if want_active:
        # Active checks are private/local only, bounded, and logged — and opt-in.
        # They run only when explicitly enabled in config AND requested here.
        if not app.config.active_checks:
            print(
                "error: --active requires BASTION_ACTIVE_CHECKS=true. Active checks are "
                "private/local only (a bounded loopback liveness confirmation of your own "
                "services), opt-in, and logged. Nothing was run. Use the default passive "
                "review, or set BASTION_ACTIVE_CHECKS=true to enable active mode.",
                file=sys.stderr,
            )
            return 2
        assets = app.assets.scan_local(active=True, persist=True)
        mode = "active-local"
    else:
        assets = app.assets.scan_local(active=False, persist=True)
        mode = "passive"

    if args.json:
        _print_json([a.to_dict() for a in assets])
        return 0
    print(f"Assets & Exposure — {len(assets)} local services reviewed ({mode})\n")
    for a in assets:
        tag = "risky" if a.risky else "     "
        dev = " dev" if a.is_dev_server else ""
        print(f"{_sev_marker(a.severity.value)} {tag} {a.service_name:22} {a.host}:{a.port} "
              f"({a.exposure.value}){dev}")
    if not assets:
        print("  (no listening services observed, or none classified as noteworthy)")
    return 0


def cmd_report(args) -> int:
    app = _app(args)
    if args.report_cmd != "build":
        print("error: unknown report subcommand", file=sys.stderr)
        return 2
    out_dir = Path(args.out) if args.out else app.config.report_dir
    formats = _parse_formats(args.formats)
    report = app.build_report(out_dir=out_dir, formats=formats, include_bundle=not args.no_bundle)
    if args.json:
        _print_json({"report_id": report.report_id, "summary": report.summary.to_dict(),
                     "output_paths": report.output_paths})
        return 0
    print(f"Report built: {report.report_id}")
    print(f"  {report.summary.headline}")
    print("  Outputs:")
    for fmt, path in report.output_paths.items():
        print(f"    {fmt:16} {path}")
    return 0


def cmd_correlate(args) -> int:
    app = _app(args)
    result = app.correlate()
    if args.json:
        _print_json(result)
        return 0
    print("Correlation — cross-engine view\n")
    print(result["summary"])
    print()
    for c in result["clusters"][:20]:
        gap = " [COVERAGE GAP]" if c["coverage_gap"] else ""
        print(f"{_sev_marker(c['severity'])} {c['label']}{gap}")
        print(f"        {c['narrative']}")
    return 0


def cmd_coverage(args) -> int:
    app = _app(args)
    cov = app.detection_coverage()
    if args.json:
        _print_json(cov)
        return 0
    print(f"Detection Coverage — {cov['tactics_covered']}/{cov['tactics_total']} ATT&CK tactics, "
          f"{cov['techniques_covered']} techniques\n")
    for row in cov["by_tactic"]:
        mark = "  ok  " if row["covered"] else " GAP  "
        print(f"[{mark}] {row['tactic_id']} {row['tactic']:26} techniques: {row['technique_count']}")
    if cov["gaps"]:
        print("\nTactic gaps (no rule coverage): " + ", ".join(cov["gaps"]))
    return 0


def cmd_lint(args) -> int:
    app = _app(args)
    lint = app.lint_detections()
    if args.json:
        _print_json(lint)
        return 0 if lint["clean"] else 1
    if lint["clean"]:
        print("Detection lint: all rules clean.")
        return 0
    print(f"Detection lint: {lint['errors']} error(s), {lint['warnings']} warning(s)\n")
    for rid, issues in lint["by_rule"].items():
        for i in issues:
            print(f"  [{i['severity']:7}] {rid:16} {i['code']}: {i['message']}")
    return 0 if lint["errors"] == 0 else 1


def cmd_forecast_export(args) -> int:
    app = _app(args)
    fmt = args.format
    try:
        content = app.export_threat_intel(fmt)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(content, encoding="utf-8")
        print(f"Wrote {fmt} export to {args.out}")
    else:
        print(content)
    return 0


def cmd_load_custom(args) -> int:
    app = _app(args)
    rules_dir = Path(args.rules) if getattr(args, "rules", None) else None
    result = app.load_custom_rules(rules_dir)
    if args.json:
        _print_json(result)
        return 0 if not result.get("rejected") else 1
    if result.get("note"):
        print(result["note"])
        return 0
    print(f"Custom rules — {result['accepted_count']} accepted, {result['rejected_count']} rejected "
          f"(from {result['rules_dir']})\n")
    for r in result.get("accepted", []):
        print(f"  [ok]   {r.get('id', '?'):16} {r.get('name', '')[:50]}  (DRAFT until validated)")
    for r in result.get("rejected", []):
        print(f"  [FAIL] {str(r.get('id') or r.get('file')):16} {'; '.join(r.get('errors', []))[:80]}")
    return 0 if not result.get("rejected") else 1


def cmd_evidence(args) -> int:
    app = _app(args)
    if args.evidence_cmd != "verify":
        print("error: unknown evidence subcommand", file=sys.stderr)
        return 2
    path = Path(args.bundle)
    if not path.exists():
        print(f"error: bundle not found: {path}", file=sys.stderr)
        return 2
    result = app.evidence_center.verify_bundle(path)
    if args.json:
        _print_json(result)
        return 0 if result.get("ok") else 1
    status = "OK" if result.get("ok") else "FAILED"
    print(f"Evidence bundle: {status}")
    print(f"Report ID: {result.get('report_id') or '(unknown)'}")
    print(f"Entries verified: {result.get('entry_count', 0)}")
    problems = result.get("problems", []) or []
    print(f"Problems: {len(problems)}")
    for p in problems:
        print(f"  - {p}")
    return 0 if result.get("ok") else 1


def cmd_serve(args) -> int:
    app = _app(args)
    from .web.server import serve
    host = args.host or app.config.host
    port = args.port or app.config.port
    serve(app, host=host, port=port)
    return 0


# --- helpers -----------------------------------------------------------------
def _parse_formats(spec: str | None) -> list[ReportFormat] | None:
    if not spec:
        return None
    out: list[ReportFormat] = []
    for token in spec.split(","):
        token = token.strip().lower()
        if not token:
            continue
        match = ReportFormat.coerce(token)
        if match:
            out.append(match)
    return out or None


def _report_from_findings(app, findings, *, title, modules, out_dir):
    from .schemas import BastionReport
    report = BastionReport(title=title, modules=modules, findings=findings)
    report.recompute_summary()
    app.report_center.write(report, out_dir, [
        ReportFormat.HTML, ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.CSV,
    ])
    app.evidence_center.build_bundle(report, out_dir)
    return report


# --- parser ------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bastion",
        description="GreyNOC Bastion — local-first defensive cyber operations platform.",
    )
    p.add_argument("--version", action="version", version=f"GreyNOC Bastion {__version__}")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    # Shared parent so `--json` also works AFTER the subcommand
    # (e.g. both `bastion --json status` and `bastion status --json`).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="emit machine-readable JSON")

    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("status", parents=[common], help="show configuration and stored-record counts")
    sp.set_defaults(func=cmd_status)

    dp = sub.add_parser("doctor", parents=[common], help="run safety and configuration self-checks")
    dp.set_defaults(func=cmd_doctor)

    fp = sub.add_parser("forecast", help="threat forecast")
    fsub = fp.add_subparsers(dest="forecast_cmd", required=True)
    fd = fsub.add_parser("demo", parents=[common], help="ranked forecast from bundled fixtures")
    fd.add_argument("--pretty", action="store_true", help="show drivers and remediation")
    fd.add_argument("--sectors", help="comma-separated sector relevance hints")
    fd.add_argument("--persist", action="store_true", help="store threats + findings")
    fd.set_defaults(func=cmd_forecast)
    fi = fsub.add_parser("ingest", parents=[common],
                         help="forecast from a CVE-feed JSON fixture (offline) or a guarded URL")
    fisrc = fi.add_mutually_exclusive_group(required=True)
    fisrc.add_argument("--fixture", help="path to a CVE feed JSON (offline)")
    fisrc.add_argument("--url", help="HTTPS CVE-feed URL; requires BASTION_LIVE_FETCH=true and allowlist")
    fi.add_argument("--sectors", help="comma-separated sector relevance hints")
    fi.add_argument("--pretty", action="store_true")
    fi.set_defaults(func=cmd_forecast, persist=True)
    fx = fsub.add_parser("export", parents=[common], help="export stored threats as STIX 2.1 or ATT&CK Navigator")
    fx.add_argument("--format", choices=["stix", "navigator"], required=True)
    fx.add_argument("--out", help="write to this file (default: stdout)")
    fx.set_defaults(func=cmd_forecast_export)

    ip = sub.add_parser("identities", help="identity blast radius scan")
    isub = ip.add_subparsers(dest="identities_cmd", required=True)
    isc = isub.add_parser("scan", parents=[common], help="scan a repo/folder for non-human identities")
    isc.add_argument("path", help="repo or project folder to scan")
    isc.add_argument("--out", help="write a report to this folder")
    isc.set_defaults(func=cmd_identities)

    dep = sub.add_parser("detections", help="detection validation range")
    desub = dep.add_subparsers(dest="detections_cmd", required=True)
    dev = desub.add_parser("validate", parents=[common], help="validate a scenario or the whole pack")
    dev.add_argument("--scenario", help="path to a scenario JSON")
    dev.add_argument("--all", action="store_true", help="validate the whole rule pack")
    dev.add_argument("--pretty", action="store_true")
    dev.set_defaults(func=cmd_detections)
    dco = desub.add_parser("coverage", parents=[common], help="ATT&CK coverage map + tactic gaps")
    dco.set_defaults(func=cmd_coverage)
    dln = desub.add_parser("lint", parents=[common], help="static-lint the detection rule pack")
    dln.set_defaults(func=cmd_lint)
    dlc = desub.add_parser("load-custom", parents=[common],
                           help="load user detection rules (ReDoS-screened; accepted stay drafts)")
    dlc.add_argument("--rules", help="directory of custom rule JSON files (default: BASTION_RULES_DIR)")
    dlc.set_defaults(func=cmd_load_custom)

    pp = sub.add_parser("playbooks", help="operator playbooks")
    psub = pp.add_subparsers(dest="playbooks_cmd", required=True)
    pl = psub.add_parser("list", parents=[common], help="list available playbooks")
    pl.set_defaults(func=cmd_playbooks)
    psh = psub.add_parser("show", parents=[common], help="show one playbook")
    psh.add_argument("name", help="playbook slug or name")
    psh.set_defaults(func=cmd_playbooks)

    ap = sub.add_parser("assets", help="local asset & exposure review")
    asub = ap.add_subparsers(dest="assets_cmd", required=True)
    asl = asub.add_parser("scan-local", parents=[common],
                          help="review local listening services (passive by default)")
    asmode = asl.add_mutually_exclusive_group()
    asmode.add_argument("--passive", action="store_true",
                        help="passive only (default) — reads the local socket table, sends no packets")
    asmode.add_argument("--active", action="store_true",
                        help="bounded loopback-only liveness confirmation; requires BASTION_ACTIVE_CHECKS=true")
    asl.set_defaults(func=cmd_assets)

    rp = sub.add_parser("report", help="build reports")
    rsub = rp.add_subparsers(dest="report_cmd", required=True)
    rb = rsub.add_parser("build", parents=[common], help="build a consolidated report from stored findings")
    rb.add_argument("--out", help="output folder")
    rb.add_argument("--formats", help="comma-separated: html,markdown,json,csv,sarif,pdf")
    rb.add_argument("--no-bundle", action="store_true", help="skip the evidence bundle")
    rb.set_defaults(func=cmd_report)

    cor = sub.add_parser("correlate", parents=[common],
                         help="cross-engine correlation view + coverage gaps")
    cor.set_defaults(func=cmd_correlate)

    evp = sub.add_parser("evidence", help="evidence bundle tools")
    evsub = evp.add_subparsers(dest="evidence_cmd", required=True)
    evv = evsub.add_parser("verify", parents=[common], help="verify an evidence bundle's integrity")
    evv.add_argument("bundle", help="path to a .evidence.zip bundle")
    evv.set_defaults(func=cmd_evidence)

    svp = sub.add_parser("serve", help="serve the local dashboard (127.0.0.1)")
    svp.add_argument("--host", default=None, help="bind host (default 127.0.0.1)")
    svp.add_argument("--port", type=int, default=None, help="bind port (default 8788)")
    svp.set_defaults(func=cmd_serve)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Propagate the top-level --json to handlers (they read args.json).
    if not hasattr(args, "json"):
        args.json = False
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
