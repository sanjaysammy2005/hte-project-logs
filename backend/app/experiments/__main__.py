"""Run an experiment configuration from the command line.

    docker compose run --rm backend python -m app.experiments experiments/smoke.json \
        --git-commit "$(git rev-parse --short HEAD)"

Long runs belong here rather than behind an HTTP request.
"""

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy.orm import Session

from app.db.session import get_engine
from app.experiments.runner import ExperimentConfig, ExperimentConfigError, create_run, execute_run
from app.provenance.rules import load_rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.experiments")
    parser.add_argument("config", type=Path, help="JSON experiment configuration")
    parser.add_argument("--git-commit", default=None)
    args = parser.parse_args(argv)
    try:
        config = ExperimentConfig.from_dict(json.loads(args.config.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ExperimentConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    with Session(get_engine(), expire_on_commit=False) as db:
        run = create_run(db, config, git_commit=args.git_commit)
        print(f"experiment run {run.id}")
        execute_run(db, run.id, load_rules(), progress=lambda m: print(m, flush=True))
    print(f"done: experiment run {run.id}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
