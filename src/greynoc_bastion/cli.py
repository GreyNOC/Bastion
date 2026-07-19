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
    bastion detections replay --file <log.jsonl>
    bastion playbooks list
    bastion playbooks show <name>
    bastion assets scan-local --passive
    bastion cases open|triage|list|show|assign|note|close|reopen
    bastion users add|list|set-role|set-password|enable|disable|delete
    bastion schedule add|list|remove|enable|disable|run-due
    bastion orchestrate list|run <workflow>
    bastion notify test
    bastion audit
    bastion evidence keygen|sign|verify
    bastion report build --out <folder>
    bastion serve --host 127.0.0.1 --port 8788
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __product__, __version__
from .app import BastionApp
from .config import load_config
from .schemas import ReportFormat
from .services import signing


# --- small output helpers ----------------------------------------------------
def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def _sev_marker(sev: str) -> str:
    return {
        "critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
        "low": "[LOW ]", "info": "[INFO]",
    }.get(sev, "[    ]")


# --- colour + landing page ---------------------------------------------------
# ASCII-only banner (renders identically on Windows cmd, PowerShell, and POSIX
# terminals — no box-drawing glyphs that legacy code pages would mangle).
_BANNER_LINES = [
    r"  ____    _    ____ _____ ___ ___  _   _ ",
    r" | __ )  / \  / ___|_   _|_ _/ _ \| \ | |",
    r" |  _ \ / _ \ \___ \ | |  | | | | |  \| |",
    r" | |_) / ___ \ ___) || |  | | |_| | |\  |",
    r" |____/_/   \_\____/ |_| |___\___/|_| \_|",
]


def _use_color() -> bool:
    """Colour only for an interactive terminal, and never when NO_COLOR is set
    or TERM is 'dumb' (honours the https://no-color.org convention)."""
    return (
        sys.stdout.isatty()
        and not os.environ.get("NO_COLOR")
        and os.environ.get("TERM") != "dumb"
    )


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _use_color() else text


def cmd_welcome(args) -> int:
    """The landing page: banner, live safety posture, and the single most useful
    next step for where this install currently is. Shown for a bare ``bastion``.

    It must never crash — a fresh or unwritable environment still gets the
    banner and quick-start, just without the live status line.
    """
    posture: str | None = None
    counts: dict = {}
    live_fetch = active = False
    try:
        app = _app(args)
        status = app.status()
        posture = status["safety_posture"]
        counts = status["counts"]
        live_fetch = bool(status["config"].get("live_fetch"))
        active = bool(status["config"].get("active_checks"))
    except Exception:  # noqa: BLE001  # nosec B110 - landing page is best-effort, never fatal
        pass  # a fresh/unwritable env still gets the banner + quick-start below

    print()
    for line in _BANNER_LINES:
        print(_c(line, "36"))
    print("  " + _c(f"{__product__} {__version__}", "1;36")
          + _c("  ·  local-first defensive console", "2"))

    if posture:
        label, code = {
            "hardened": ("hardened", "1;32"),
            "attention": ("attention", "1;33"),
            "elevated": ("elevated", "1;31"),
        }.get(posture, (posture, "1;33"))
        flags = []
        if live_fetch:
            flags.append("live-fetch ON")
        if active:
            flags.append("active-checks ON")
        suffix = _c("  (" + ", ".join(flags) + ")", "2") if flags else ""
        print("  safety posture: " + _c("● " + label, code) + suffix)
    print()

    total = sum(counts.values()) if counts else 0
    if total == 0:
        print(_c("  You're all set — but the store is empty. Try one of these:", "1"))
        print("    " + _c("bastion forecast demo --persist", "32")
              + "        rank threats from bundled offline intel")
        print("    " + _c("bastion identities scan <path>", "32")
              + "         find leaked keys/tokens in a repo (masked)")
        print("    " + _c("bastion assets scan-local --passive", "32")
              + "    review your local listening services")
        print("    " + _c("bastion orchestrate run full-sweep", "32")
              + "     run every engine end-to-end in one go")
    else:
        print(_c(f"  {total} records stored. Pick up where you left off:", "1"))
        print("    " + _c("bastion serve", "32")
              + "                          open the dashboard (http://127.0.0.1:8788)")
        print("    " + _c("bastion correlate", "32")
              + "                      cross-engine view + coverage gaps")
        print("    " + _c("bastion cases triage", "32")
              + "                   open cases for untracked high findings")
        print("    " + _c("bastion report build --out ./out", "32")
              + "       build an evidence-backed report")

    print()
    print(_c("  bastion doctor", "2") + _c("   run safety self-checks    ", "2")
          + _c("bastion --help", "2") + _c("   all commands", "2"))
    print(_c("  Everything runs on your machine. Network fetching is OFF by default.", "2"))
    print()
    return 0


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
    sb = status.get("signing_backends", {})
    sign_schemes = ["hmac", *(_scheme_short(s) for s in sb.get("asymmetric_schemes", []))]
    print(f"  Signing          : {', '.join(sign_schemes)}")
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
            if args.epss or args.kev:
                print("error: --epss/--kev currently require --fixture", file=sys.stderr)
                return 2
            # Guarded live fetch (off by default). Refuses unless live fetching
            # is enabled; HTTPS-only, allowlisted, SSRF-blocked, size/time-capped.
            # Cache modes: --refresh forces live, --offline uses cache only.
            try:
                threats = app.threat_forecast.ingest_url(
                    url, sectors=sectors, persist=True,
                    refresh=getattr(args, "refresh", False),
                    offline=getattr(args, "offline", False),
                )
            except Exception as exc:  # noqa: BLE001 - surface a clear operator message
                print(f"error: live fetch refused or failed: {exc}", file=sys.stderr)
                return 2
        elif args.fixture:
            threats = app.threat_forecast.ingest(
                Path(args.fixture), sectors=sectors, persist=True,
                epss_path=Path(args.epss) if args.epss else None,
                kev_path=Path(args.kev) if args.kev else None,
            )
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
            if t.forecast:
                if t.forecast.status == "observed":
                    print("           timing: exploitation already observed (CISA KEV)")
                elif (t.forecast.status == "estimated"
                      and t.forecast.exploit_probability is not None):
                    print(
                        f"           timing: EPSS 30d={t.forecast.exploit_probability:.1%}; "
                        f"p50={t.forecast.horizon_days_p50}d p90={t.forecast.horizon_days_p90}d "
                        "(constant-hazard assumption)"
                    )
                else:
                    print("           timing: insufficient data (no EPSS observation)")
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


def _default_key_path(app) -> Path:
    return app.config.home / "keys" / "evidence.key"


def _default_pub_path(app) -> Path:
    return app.config.home / "keys" / "evidence.pub"


def _scheme_short(scheme: str) -> str:
    """Map a canonical asymmetric scheme id to its short CLI alias."""
    return {
        signing.SCHEME_ED25519: "ed25519",
        signing.SCHEME_MLDSA65: "ml-dsa-65",
        signing.SCHEME_HYBRID: "hybrid",
    }.get(scheme, scheme)


def cmd_evidence(args) -> int:
    app = _app(args)

    if args.evidence_cmd == "backends":
        backend = app.evidence_center.crypto_backend_status()
        if args.json:
            _print_json(backend)
            return 0
        print("Evidence signing backends")
        print("  HMAC-SHA256 (shared key) : available (zero dependencies)")
        cg = "available" if backend["cryptography_installed"] else "not installed"
        ver = f" v{backend['cryptography_version']}" if backend["cryptography_version"] else ""
        print(f"  cryptography backend     : {cg}{ver}")
        print(f"  Ed25519 (classical)      : {'available' if backend['ed25519_available'] else 'unavailable'}")
        print(f"  ML-DSA-65 (post-quantum) : {'available' if backend['mldsa_available'] else 'unavailable'}")
        schemes = ["hmac", *(_scheme_short(s) for s in backend["asymmetric_schemes"])]
        print(f"  usable schemes           : {', '.join(schemes)}")
        if not backend["cryptography_installed"]:
            print("  (install asymmetric/PQC signing with:  pip install 'greynoc-bastion[pqc]')")
        return 0

    if args.evidence_cmd == "keygen":
        if args.scheme == "hmac":
            key_path = Path(args.key) if args.key else _default_key_path(app)
            try:
                written = app.evidence_center.generate_key(key_path, force=args.force)
            except FileExistsError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            app.db.audit("evidence_keygen", actor=_actor(), detail=f"scheme=hmac key={written}")
            if args.json:
                _print_json({"scheme": "hmac-sha256-detached", "key": written})
                return 0
            print(f"Signing key written to {written} (owner-only permissions).")
            print("Scheme: hmac-sha256-detached (shared-key tamper evidence).")
            print("Share it ONLY out-of-band with parties who must verify your bundles.")
            return 0
        # Asymmetric / hybrid-PQC keypair.
        priv_path = Path(args.key) if args.key else _default_key_path(app)
        pub_path = Path(args.pub) if args.pub else _default_pub_path(app)
        try:
            info = app.evidence_center.generate_keypair(
                priv_path, pub_path, scheme=args.scheme, force=args.force)
        except signing.SigningBackendUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        app.db.audit("evidence_keygen", actor=_actor(),
                     detail=f"scheme={info['scheme']} key_id={info['key_id']}")
        if args.json:
            _print_json(info)
            return 0
        print(f"Keypair generated (scheme: {info['scheme']}).")
        print(f"  private key : {info['private_key']} (owner-only — keep secret)")
        print(f"  public key  : {info['public_key']} (share this to let others verify)")
        print(f"  algorithms  : {', '.join(info['algorithms'])}")
        print(f"  key id      : {info['key_id']}")
        print(f"  trust model : {signing.trust_model(info['scheme'])}")
        return 0

    if args.evidence_cmd == "sign":
        bundle = Path(args.bundle)
        if not bundle.exists():
            print(f"error: bundle not found: {bundle}", file=sys.stderr)
            return 2
        key_path = Path(args.key) if args.key else _default_key_path(app)
        try:
            info = app.evidence_center.sign_bundle(bundle, key_path=key_path)
        except (FileNotFoundError, ValueError, PermissionError,
                signing.SigningBackendUnavailable) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        app.db.audit("evidence_signed", actor=_actor(),
                     detail=f"bundle={bundle.name} scheme={info['scheme']} key_id={info['key_id']}")
        if args.json:
            _print_json(info)
            return 0
        print(f"Signed: {info['signature_path']}")
        print(f"  scheme    : {info['scheme']}")
        if info.get("algorithms"):
            print(f"  algorithms: {', '.join(info['algorithms'])}")
        print(f"  key id    : {info['key_id']}")
        print(f"  bundle sha: {info['bundle_sha256'][:32]}…")
        return 0

    if args.evidence_cmd == "verify":
        bundle_path = Path(args.bundle)
        if not bundle_path.exists():
            print(f"error: bundle not found: {bundle_path}", file=sys.stderr)
            return 2
        result = app.evidence_center.verify_bundle(bundle_path)
        sig_result = None
        if args.key or args.pubkey or args.signature:
            key_path = Path(args.key) if args.key else _default_key_path(app)
            # Offer the default public key too, so `verify --pubkey`-less runs on
            # an asymmetric bundle can still find it; scheme dispatch picks which.
            verify_pub: Path | None
            if args.pubkey:
                verify_pub = Path(args.pubkey)
            else:
                default_pub = _default_pub_path(app)
                verify_pub = default_pub if default_pub.is_file() else None
            try:
                sig_result = app.evidence_center.verify_signature(
                    bundle_path, key_path=key_path, public_key_path=verify_pub,
                    signature_path=Path(args.signature) if args.signature else None)
            except (FileNotFoundError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        ok = result.get("ok") and (sig_result is None or sig_result.get("ok"))
        if args.json:
            _print_json({"integrity": result, "signature": sig_result, "ok": ok})
            return 0 if ok else 1
        status = "OK" if result.get("ok") else "FAILED"
        print(f"Evidence bundle integrity: {status}")
        print(f"Report ID: {result.get('report_id') or '(unknown)'}")
        print(f"Entries verified: {result.get('entry_count', 0)}")
        problems = result.get("problems", []) or []
        print(f"Problems: {len(problems)}")
        for p in problems:
            print(f"  - {p}")
        if sig_result is not None:
            print(f"Detached signature: {'OK' if sig_result['ok'] else 'FAILED'}")
            for p in sig_result.get("problems", []):
                print(f"  - {p}")
        return 0 if ok else 1

    print("error: unknown evidence subcommand", file=sys.stderr)
    return 2


def _actor() -> str:
    """The acting local user for CLI audit entries."""
    import getpass
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:  # noqa: BLE001 - some containers have no passwd entry
        return "cli:unknown"


def _read_new_password(prompt: str = "New password: ") -> str:
    """Read a password without echo, with confirmation. Never from argv."""
    import getpass as _gp
    if not sys.stdin.isatty():
        # Non-interactive (tests, provisioning scripts): single line on stdin.
        return sys.stdin.readline().rstrip("\n")
    first = _gp.getpass(prompt)
    second = _gp.getpass("Repeat password: ")
    if first != second:
        raise ValueError("passwords do not match")
    return first


def cmd_cases(args) -> int:
    from .services.case_management import CaseError
    app = _app(args)
    actor = _actor()
    try:
        if args.cases_cmd == "open":
            finding_ids = [f.strip() for f in (args.finding or "").split(",") if f.strip()]
            case = app.cases.open_case(args.title, finding_ids=finding_ids,
                                       severity=args.severity, assignee=args.assignee or "",
                                       actor=actor)
            if args.json:
                _print_json(case.to_dict())
                return 0
            print(f"Opened {case.case_id} [{case.severity.value}] {case.title}")
            return 0
        if args.cases_cmd == "triage":
            opened = app.cases.open_from_findings(min_severity=args.min_severity, actor=actor)
            if args.json:
                _print_json([c.to_dict() for c in opened])
                return 0
            print(f"Triage sweep: {len(opened)} new case(s) opened "
                  f"for untracked {args.min_severity}+ findings.")
            for c in opened:
                print(f"  {c.case_id} [{c.severity.value}] {c.title[:70]}")
            return 0
        if args.cases_cmd == "list":
            cases = app.cases.workqueue() if args.queue else app.cases.list_cases(
                status=args.status, assignee=args.assignee)
            if args.json:
                _print_json([c.to_dict() for c in cases])
                return 0
            label = "workqueue (open; unassigned first)" if args.queue else "cases"
            print(f"Case management — {len(cases)} {label}\n")
            for c in cases:
                who = c.assignee or "(unassigned)"
                print(f"{_sev_marker(c.severity.value)} {c.case_id}  {c.status.value:12} "
                      f"{who:16} {c.title[:56]}")
            summary = app.cases.summary()
            print(f"\nopen={summary['open']} in_progress={summary['in_progress']} "
                  f"closed={summary['closed']} unassigned={summary['unassigned']}")
            return 0
        if args.cases_cmd == "show":
            found = app.cases.get(args.case_id)
            if not found:
                print(f"error: case not found: {args.case_id}", file=sys.stderr)
                return 2
            if args.json:
                _print_json(found.to_dict())
                return 0
            print(f"# {found.title}  ({found.case_id})")
            print(f"Status: {found.status.value} | Severity: {found.severity.value} | "
                  f"Assignee: {found.assignee or '(unassigned)'}")
            print(f"Created: {found.created_at} by {found.created_by} | Updated: {found.updated_at}")
            if found.closed_at:
                print(f"Closed: {found.closed_at} — {found.close_reason}")
            if found.finding_ids:
                print(f"Findings: {', '.join(found.finding_ids)}")
            for n in found.notes:
                print(f"  [{n.at}] {n.author}: {n.text}")
            return 0
        if args.cases_cmd == "assign":
            case = app.cases.assign(args.case_id, args.assignee, actor=actor)
            print(f"{case.case_id} assigned to {case.assignee or '(unassigned)'} "
                  f"({case.status.value})")
            return 0
        if args.cases_cmd == "note":
            case = app.cases.add_note(args.case_id, args.text, actor=actor)
            print(f"Note added to {case.case_id} ({len(case.notes)} note(s)).")
            return 0
        if args.cases_cmd == "close":
            case = app.cases.close(args.case_id, reason=args.reason, actor=actor)
            print(f"{case.case_id} closed: {case.close_reason}")
            return 0
        if args.cases_cmd == "reopen":
            case = app.cases.reopen(args.case_id, actor=actor)
            print(f"{case.case_id} reopened ({case.status.value}).")
            return 0
    except CaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("error: unknown cases subcommand", file=sys.stderr)
    return 2


def cmd_users(args) -> int:
    from .auth import AuthError
    app = _app(args)
    actor = _actor()
    try:
        if args.users_cmd == "add":
            password = _read_new_password()
            info = app.operators.add(args.username, password, args.role, actor=actor)
            print(f"Operator '{info['username']}' added with role '{info['role']}'.")
            if app.operators.multi_operator_mode():
                print("Multi-operator mode is ON: the dashboard now requires login.")
            return 0
        if args.users_cmd == "list":
            ops = app.operators.list_operators()
            if args.json:
                _print_json(ops)
                return 0
            print(f"Operators — {len(ops)} account(s)\n")
            for o in ops:
                state = "disabled" if o["disabled"] else "enabled"
                print(f"  {o['username']:24} {o['role']:10} {state:9} created {o['created_at']}")
            if not ops:
                print("  (none — dashboard runs in single-operator local-trust mode)")
            return 0
        if args.users_cmd == "set-role":
            app.operators.set_role(args.username, args.role, actor=actor)
            print(f"Role for '{args.username}' set to '{args.role}'.")
            return 0
        if args.users_cmd == "set-password":
            password = _read_new_password()
            app.operators.set_password(args.username, password, actor=actor)
            print(f"Password updated for '{args.username}'.")
            return 0
        if args.users_cmd in ("enable", "disable"):
            app.operators.set_disabled(args.username, args.users_cmd == "disable", actor=actor)
            print(f"Operator '{args.username}' {args.users_cmd}d.")
            return 0
        if args.users_cmd == "delete":
            app.operators.delete(args.username, actor=actor)
            print(f"Operator '{args.username}' deleted.")
            return 0
    except (AuthError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("error: unknown users subcommand", file=sys.stderr)
    return 2


def cmd_schedule(args) -> int:
    from .services.scheduler import ScheduleError
    app = _app(args)
    actor = _actor()
    try:
        if args.schedule_cmd == "add":
            record = app.scheduler.add(
                args.name, kind=args.kind, interval_hours=args.every,
                workflow=args.workflow or "", deliver_to=args.deliver_to or "", actor=actor)
            if args.json:
                _print_json(record)
                return 0
            print(f"Schedule {record['schedule_id']} added: {record['name']!r} "
                  f"({record['kind']}, every {record['interval_hours']}h).")
            print("Nothing runs by itself — wire `bastion schedule run-due` to cron/systemd.")
            return 0
        if args.schedule_cmd == "list":
            schedules = app.scheduler.list_schedules()
            if args.json:
                _print_json(schedules)
                return 0
            print(f"Schedules — {len(schedules)}\n")
            for s in schedules:
                state = "on " if s.get("enabled") else "OFF"
                target = s.get("workflow") or "consolidated report"
                print(f"  [{state}] {s['schedule_id']}  {s.get('name', ''):24} {s.get('kind', ''):9} "
                      f"{target:20} every {s.get('interval_hours')}h  next {s.get('next_run_at', '')}")
            return 0
        if args.schedule_cmd == "remove":
            ok = app.scheduler.remove(args.schedule_id, actor=actor)
            print("Removed." if ok else "Nothing removed (unknown id).")
            return 0 if ok else 2
        if args.schedule_cmd in ("enable", "disable"):
            app.scheduler.set_enabled(args.schedule_id, args.schedule_cmd == "enable", actor=actor)
            print(f"Schedule {args.schedule_id} {args.schedule_cmd}d.")
            return 0
        if args.schedule_cmd == "run-due":
            outcomes = app.scheduler.run_due(actor=actor)
            if args.json:
                _print_json(outcomes)
                return 0 if all(o["ok"] for o in outcomes) else 1
            if not outcomes:
                print("Nothing due.")
                return 0
            for o in outcomes:
                mark = "ok" if o["ok"] else "FAIL"
                print(f"[{mark:4}] {o['schedule_id']} ({o['kind']}): "
                      f"{o.get('detail') or o.get('error', '')}")
            return 0 if all(o["ok"] for o in outcomes) else 1
    except ScheduleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("error: unknown schedule subcommand", file=sys.stderr)
    return 2


def cmd_orchestrate(args) -> int:
    app = _app(args)
    if args.orchestrate_cmd == "list":
        workflows = app.orchestrator.list_workflows()
        if args.json:
            _print_json(workflows)
            return 0
        print(f"Workflows — {len(workflows)}\n")
        for wf in workflows:
            print(f"  {wf['name']:22} {wf['description']}")
            print(f"  {'':22} steps: {' -> '.join(wf['steps'])}")
        return 0
    if args.orchestrate_cmd == "run":
        try:
            result = app.orchestrator.run(args.name, actor=_actor())
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.json:
            _print_json(result)
            return 0 if result["ok"] else 1
        print(f"Workflow '{result['workflow']}' — {'OK' if result['ok'] else 'FAILURES'}\n")
        for s in result["steps"]:
            mark = "ok" if s["ok"] else "FAIL"
            print(f"[{mark:4}] {s['step']:12} {s['summary']}  ({s['seconds']}s)")
        return 0 if result["ok"] else 1
    print("error: unknown orchestrate subcommand", file=sys.stderr)
    return 2


def cmd_replay(args) -> int:
    from .services.telemetry_ingest import TelemetryIngestError
    app = _app(args)
    try:
        result = app.telemetry.replay_file(
            Path(args.file), max_bytes=args.max_bytes, persist=not args.no_persist,
            actor=_actor())
    except TelemetryIngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        _print_json(result)
        return 0
    print(f"Live telemetry replay — {result['events']} events from {result['file']}")
    if result["skipped_lines"]:
        print(f"  ({result['skipped_lines']} malformed/over-cap lines skipped)")
    print(f"  {len(result['rules_fired'])}/{result['rules_evaluated']} rules fired, "
          f"{result['alerts']} alert(s), {len(result['incidents'])} incident(s)\n")
    for r in result["rules_fired"]:
        print(f"{_sev_marker(r['severity'])} {r['rule_id']:16} x{r['alerts']}  {r['rule_name'][:56]}")
    for i in result["incidents"]:
        stage = "multi-stage" if i["multi_stage"] else "single-rule"
        print(f"  incident: host={i['host']} rules={','.join(i['rule_ids'])} "
              f"dwell={i['dwell_minutes']}m ({stage})")
    return 0


def cmd_notify(args) -> int:
    app = _app(args)
    if args.notify_cmd != "test":
        print("error: unknown notify subcommand", file=sys.stderr)
        return 2
    result = app.notifications.notify(
        "test", "Bastion notification test",
        detail="If you can read this, the notification fabric is delivering.",
        severity="info")
    if args.json:
        _print_json(result)
        return 0 if result["enabled"] and all(d["ok"] for d in result["deliveries"]) else 1
    if not result["enabled"]:
        print("Notifications are DISABLED (safe default). Set BASTION_NOTIFY=true to enable;")
        print("optionally BASTION_NOTIFY_WEBHOOK_URL + BASTION_NOTIFY_ALLOWLIST for a webhook sink.")
        return 1
    for d in result["deliveries"]:
        mark = "ok" if d["ok"] else "FAIL"
        target = d.get("target") or d.get("status") or d.get("error", "")
        print(f"[{mark:4}] {d['sink']:8} {target}")
    return 0 if all(d["ok"] for d in result["deliveries"]) else 1


def cmd_audit(args) -> int:
    app = _app(args)
    entries = app.db.recent_audit(limit=args.limit)
    if args.json:
        _print_json(entries)
        return 0
    print(f"Audit trail — most recent {len(entries)} entrie(s)\n")
    for e in entries:
        detail = f"  {e['detail']}" if e.get("detail") else ""
        corr = f"  [{e['correlation_id']}]" if e.get("correlation_id") else ""
        print(f"{e['ts']}  {e['action']:26} actor={e['actor']}{detail}{corr}")
    return 0


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

    # Not required: a bare `bastion` shows the landing page (see main()).
    sub = p.add_subparsers(dest="command", required=False)

    wp = sub.add_parser("welcome", parents=[common],
                        help="show the landing page (also shown when no command is given)")
    wp.set_defaults(func=cmd_welcome)

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
    fi.add_argument("--epss", help="FIRST EPSS JSON export/API response to join by CVE (with --fixture)")
    fi.add_argument("--kev", help="CISA KEV catalog JSON to join by CVE (with --fixture)")
    ficache = fi.add_mutually_exclusive_group()
    ficache.add_argument("--refresh", action="store_true",
                         help="with --url: force a live fetch, ignoring any fresh cache")
    ficache.add_argument("--offline", action="store_true",
                         help="with --url: serve only from the local cache; never touch the network")
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
    drp = desub.add_parser("replay", parents=[common],
                           help="replay the rule pack over a LOCAL log file (JSONL or JSON array)")
    drp.add_argument("--file", required=True, help="local log file of events")
    drp.add_argument("--max-bytes", type=int, default=25 * 1024 * 1024,
                     help="refuse files larger than this (default 25MB)")
    drp.add_argument("--no-persist", action="store_true",
                     help="analyze only; do not store findings")
    drp.set_defaults(func=cmd_replay)

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
    evv = evsub.add_parser("verify", parents=[common],
                           help="verify a bundle's integrity (and its signature with --key/--pubkey)")
    evv.add_argument("bundle", help="path to a .evidence.zip bundle")
    evv.add_argument("--key", help="HMAC signing key file (default: <home>/keys/evidence.key)")
    evv.add_argument("--pubkey", help="public key file for asymmetric/hybrid bundles "
                                      "(default: <home>/keys/evidence.pub)")
    evv.add_argument("--signature", help="detached signature file (default: <bundle>.sig.json)")
    evv.set_defaults(func=cmd_evidence)
    evk = evsub.add_parser("keygen", parents=[common],
                           help="generate a local signing key (HMAC, or an asymmetric/PQC keypair)")
    evk.add_argument("--scheme", default="hmac",
                     choices=["hmac", "ed25519", "ml-dsa-65", "hybrid"],
                     help="signing scheme (default: hmac). ed25519/ml-dsa-65/hybrid need "
                          "the optional 'cryptography' backend and write a keypair.")
    evk.add_argument("--key", help="where to write the (private) key "
                                   "(default: <home>/keys/evidence.key)")
    evk.add_argument("--pub", help="where to write the public key for asymmetric schemes "
                                   "(default: <home>/keys/evidence.pub)")
    evk.add_argument("--force", action="store_true", help="rotate: overwrite an existing key")
    evk.set_defaults(func=cmd_evidence)
    evs = evsub.add_parser("sign", parents=[common],
                           help="write a detached signature next to a bundle")
    evs.add_argument("bundle", help="path to a .evidence.zip bundle")
    evs.add_argument("--key", help="signing key file (HMAC or asymmetric private key; "
                                   "default: <home>/keys/evidence.key)")
    evs.set_defaults(func=cmd_evidence)
    evb = evsub.add_parser("backends", parents=[common],
                           help="show which signing schemes are available")
    evb.set_defaults(func=cmd_evidence)

    cp = sub.add_parser("cases", help="case management (assign / track / close findings)")
    csub = cp.add_subparsers(dest="cases_cmd", required=True)
    co = csub.add_parser("open", parents=[common], help="open a case")
    co.add_argument("title", help="case title")
    co.add_argument("--finding", help="comma-separated finding correlation ids to link")
    co.add_argument("--severity", help="override severity (default: derived from findings)")
    co.add_argument("--assignee", help="assign immediately")
    co.set_defaults(func=cmd_cases)
    ct = csub.add_parser("triage", parents=[common],
                         help="open cases for stored findings not yet tracked by any open case")
    ct.add_argument("--min-severity", default="high", help="severity floor (default: high)")
    ct.set_defaults(func=cmd_cases)
    cl = csub.add_parser("list", parents=[common], help="list cases / the workqueue")
    cl.add_argument("--queue", action="store_true", help="open cases only, unassigned first")
    cl.add_argument("--status", choices=["open", "in_progress", "closed"])
    cl.add_argument("--assignee")
    cl.set_defaults(func=cmd_cases)
    cs = csub.add_parser("show", parents=[common], help="show one case with notes")
    cs.add_argument("case_id")
    cs.set_defaults(func=cmd_cases)
    ca = csub.add_parser("assign", parents=[common], help="assign (or unassign) a case")
    ca.add_argument("case_id")
    ca.add_argument("assignee", help="operator name; empty string to unassign")
    ca.set_defaults(func=cmd_cases)
    cn = csub.add_parser("note", parents=[common], help="add a note to a case")
    cn.add_argument("case_id")
    cn.add_argument("text")
    cn.set_defaults(func=cmd_cases)
    cc = csub.add_parser("close", parents=[common], help="close a case")
    cc.add_argument("case_id")
    cc.add_argument("--reason", default="resolved")
    cc.set_defaults(func=cmd_cases)
    cr = csub.add_parser("reopen", parents=[common], help="reopen a closed case")
    cr.add_argument("case_id")
    cr.set_defaults(func=cmd_cases)

    up = sub.add_parser("users", help="operator accounts (auth + RBAC for the dashboard)")
    usub = up.add_subparsers(dest="users_cmd", required=True)
    ua = usub.add_parser("add", parents=[common],
                         help="add an operator (password read from prompt/stdin, never argv)")
    ua.add_argument("username")
    ua.add_argument("--role", default="admin", choices=["viewer", "operator", "admin"])
    ua.set_defaults(func=cmd_users)
    ul = usub.add_parser("list", parents=[common], help="list operator accounts (no secrets)")
    ul.set_defaults(func=cmd_users)
    ur = usub.add_parser("set-role", parents=[common], help="change an operator's role")
    ur.add_argument("username")
    ur.add_argument("role", choices=["viewer", "operator", "admin"])
    ur.set_defaults(func=cmd_users)
    upw = usub.add_parser("set-password", parents=[common], help="reset an operator's password")
    upw.add_argument("username")
    upw.set_defaults(func=cmd_users)
    for action in ("enable", "disable", "delete"):
        ux = usub.add_parser(action, parents=[common], help=f"{action} an operator account")
        ux.add_argument("username")
        ux.set_defaults(func=cmd_users)

    scp = sub.add_parser("schedule", help="report/workflow schedules (local runner)")
    ssub = scp.add_subparsers(dest="schedule_cmd", required=True)
    sa = ssub.add_parser("add", parents=[common], help="add a schedule (first run is due immediately)")
    sa.add_argument("name")
    sa.add_argument("--kind", default="report", choices=["report", "workflow"])
    sa.add_argument("--every", type=float, default=24.0, help="interval in hours (default 24)")
    sa.add_argument("--workflow", help="workflow name (required for --kind workflow)")
    sa.add_argument("--deliver-to", help="local directory to copy report outputs into")
    sa.set_defaults(func=cmd_schedule)
    sl = ssub.add_parser("list", parents=[common], help="list schedules")
    sl.set_defaults(func=cmd_schedule)
    srm = ssub.add_parser("remove", parents=[common], help="remove a schedule")
    srm.add_argument("schedule_id")
    srm.set_defaults(func=cmd_schedule)
    for action in ("enable", "disable"):
        sx = ssub.add_parser(action, parents=[common], help=f"{action} a schedule")
        sx.add_argument("schedule_id")
        sx.set_defaults(func=cmd_schedule)
    srd = ssub.add_parser("run-due", parents=[common],
                          help="execute everything due now (wire this to cron/systemd)")
    srd.set_defaults(func=cmd_schedule)

    orp = sub.add_parser("orchestrate", help="combined cross-module workflows")
    osub = orp.add_subparsers(dest="orchestrate_cmd", required=True)
    ol = osub.add_parser("list", parents=[common], help="list available workflows")
    ol.set_defaults(func=cmd_orchestrate)
    orun = osub.add_parser("run", parents=[common], help="run a named workflow")
    orun.add_argument("name")
    orun.set_defaults(func=cmd_orchestrate)

    np_ = sub.add_parser("notify", help="notification fabric (off by default)")
    nsub = np_.add_subparsers(dest="notify_cmd", required=True)
    nt = nsub.add_parser("test", parents=[common], help="send a test event to every configured sink")
    nt.set_defaults(func=cmd_notify)

    aup = sub.add_parser("audit", parents=[common], help="show the audit trail")
    aup.add_argument("--limit", type=int, default=50)
    aup.set_defaults(func=cmd_audit)

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
    # No subcommand -> the landing page (friendly first-run, not an error).
    if not hasattr(args, "func"):
        return cmd_welcome(args)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
    except Exception as exc:
        from .adapters import AdapterExecutionError
        if isinstance(exc, AdapterExecutionError):
            print(f"error: {exc}", file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":
    raise SystemExit(main())
