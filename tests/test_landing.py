"""The CLI landing page: bare `bastion`, `bastion welcome`, and colour gating."""

from __future__ import annotations

from greynoc_bastion.cli import main


def test_bare_invocation_shows_landing_not_error(monkeypatch, home, capsys):
    # A bare `bastion` must be a friendly landing page (exit 0), NOT the old
    # argparse "the following arguments are required: command" error (exit 2).
    monkeypatch.setenv("BASTION_HOME", str(home))
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "GreyNOC Bastion" in out
    assert "local-first defensive console" in out
    # The ASCII banner is present (a slice of the block-letter art).
    assert "|____/" in out


def test_welcome_subcommand_matches_bare(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    assert main(["welcome"]) == 0
    out = capsys.readouterr().out
    assert "safety posture" in out
    assert "hardened" in out  # safe defaults in a fresh home


def test_empty_store_suggests_getting_started(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    main([])
    out = capsys.readouterr().out
    assert "store is empty" in out
    assert "forecast demo --persist" in out
    assert "identities scan" in out


def test_populated_store_suggests_next_steps(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    main(["forecast", "demo", "--persist"])   # seed some records
    capsys.readouterr()                        # discard the forecast output
    main([])
    out = capsys.readouterr().out
    assert "records stored" in out
    assert "bastion serve" in out
    assert "store is empty" not in out


def test_no_ansi_when_not_a_tty(monkeypatch, home, capsys):
    # capsys is not a TTY, so the landing page must emit plain text (no colour
    # escapes) — this is what keeps piped/redirected output clean.
    monkeypatch.setenv("BASTION_HOME", str(home))
    main([])
    out = capsys.readouterr().out
    assert "\033[" not in out


def test_no_color_env_disables_colour(monkeypatch):
    # Even on a TTY, NO_COLOR / TERM=dumb must suppress escapes.
    from greynoc_bastion import cli
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli._c("x", "36") == "x"
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert cli._c("x", "36") == "x"


def test_landing_survives_broken_environment(monkeypatch, capsys):
    # If status can't be built (e.g. unusable home), the banner + quick-start
    # must still render rather than crashing.
    from greynoc_bastion import cli
    monkeypatch.setattr(cli, "_app", lambda args: (_ for _ in ()).throw(RuntimeError("boom")))
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "GreyNOC Bastion" in out
    assert "store is empty" in out   # falls back to the getting-started path
