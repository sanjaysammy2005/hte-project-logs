"""T5.1: migrations create the schema from empty and remove it again."""

from alembic import command
from sqlalchemy import Engine, inspect, text

from tests.api.conftest import alembic_config

TABLES = {"operators", "log_streams", "audit_events"}


def test_downgrade_removes_and_upgrade_recreates_schema(
    test_engine: Engine, test_database_url: str
) -> None:
    config = alembic_config(test_database_url)

    command.downgrade(config, "base")
    assert TABLES.isdisjoint(inspect(test_engine).get_table_names())

    command.upgrade(config, "head")
    assert TABLES <= set(inspect(test_engine).get_table_names())
    with test_engine.connect() as conn:
        system = conn.execute(text("SELECT kind, batch_size FROM log_streams WHERE name='system'"))
        assert system.one() == ("primary", 64)


def test_database_rejects_malformed_rows(test_engine: Engine) -> None:
    """Constraints back up the application: wrong hash length and seq without session fail."""
    insert = text(
        "INSERT INTO audit_events (stream_id, chain_index, event_type, session_id, session_seq,"
        " event_timestamp, prev_hash, entry_hash) SELECT id, 1, 'X', :sid, :seq, now(), :p, :e"
        " FROM log_streams WHERE name='system'"
    )
    for params in (
        {"sid": None, "seq": None, "p": b"\x00" * 31, "e": b"\x00" * 32},
        {"sid": None, "seq": 1, "p": b"\x00" * 32, "e": b"\x00" * 32},
    ):
        with test_engine.connect() as conn:
            try:
                conn.execute(insert, params)
                raise AssertionError(f"row accepted: {params}")
            except Exception as exc:  # noqa: BLE001 - any IntegrityError subclass
                assert "check constraint" in str(exc).lower()
