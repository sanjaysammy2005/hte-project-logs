"""Command-line administration.

Create the first admin (password read from TRACELOCK_OPERATOR_PASSWORD, else prompted):

    docker compose run --rm backend python -m app.cli create-operator --username admin --role admin
"""

import argparse
import getpass
import os
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.models import ROLES, Operator
from app.db.session import get_engine

MIN_PASSWORD_LENGTH = 12


def create_operator(session: Session, username: str, password: str, role: str) -> Operator:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if session.scalars(select(Operator.id).where(Operator.username == username)).first():
        raise ValueError(f"operator {username!r} already exists")
    operator = Operator(username=username, password_hash=hash_password(password), role=role)
    session.add(operator)
    session.commit()
    return operator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-operator", help="create a dashboard/API operator")
    create.add_argument("--username", required=True)
    create.add_argument("--role", required=True, choices=ROLES)
    args = parser.parse_args(argv)

    password = os.environ.get("TRACELOCK_OPERATOR_PASSWORD") or getpass.getpass("Password: ")
    try:
        with Session(get_engine()) as session:
            create_operator(session, args.username, password, args.role)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"created {args.role} operator {args.username!r}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
