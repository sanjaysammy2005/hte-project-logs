"""The create-operator CLI used to bootstrap the first admin."""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cli
from app.db.models import Operator


def test_create_operator_and_validation(db: Session) -> None:
    cli.create_operator(db, "root", "long-enough-pass", "admin")

    stored = db.scalars(select(Operator).where(Operator.username == "root")).one()
    assert stored.role == "admin" and stored.password_hash.startswith("$argon2id$")
    for args in (
        ("root", "long-enough-pass", "admin"),  # duplicate
        ("x", "short", "admin"),
        ("y", "long-enough-pass", "superuser"),
    ):
        with pytest.raises(ValueError):
            cli.create_operator(db, *args)


def test_main_reads_password_from_environment(
    monkeypatch: pytest.MonkeyPatch, test_engine, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr(cli, "get_engine", lambda: test_engine)
    monkeypatch.setenv("TRACELOCK_OPERATOR_PASSWORD", "long-enough-pass")

    assert cli.main(["create-operator", "--username", "ops", "--role", "auditor"]) == 0
    assert cli.main(["create-operator", "--username", "ops", "--role", "auditor"]) == 1
    out = capsys.readouterr()
    assert "created auditor operator 'ops'" in out.out
    assert "already exists" in out.err
