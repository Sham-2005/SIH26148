"""
Database Schema Migration Helper
Automatically inspects tables and adds any missing columns across SQLite/PostgreSQL
without dropping data or breaking regression tests.
"""
import logging
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.schema import MetaData

logger = logging.getLogger(__name__)


def ensure_schema_upgrades(engine: Engine, metadata: MetaData) -> None:
    """Detects and automatically adds missing columns to existing database tables."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table_name, table in metadata.tables.items():
            if table_name in existing_tables:
                existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
                for col in table.columns:
                    if col.name not in existing_cols:
                        col_type = str(col.type.compile(dialect=engine.dialect))
                        # SQLite ALTER TABLE does not support non-null columns without default
                        default_clause = ""
                        if not col.nullable:
                            if "int" in col_type.lower():
                                default_clause = " DEFAULT 0"
                            elif "bool" in col_type.lower():
                                default_clause = " DEFAULT 0"
                            else:
                                default_clause = " DEFAULT ''"

                        sql = f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}{default_clause}"
                        try:
                            conn.execute(text(sql))
                            logger.info(f"[DB MIGRATION] Added column {table_name}.{col.name} ({col_type})")
                        except Exception as e:
                            logger.warning(f"[DB MIGRATION] Could not add column {table_name}.{col.name}: {e}")
