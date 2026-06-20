"""baseline_schema

Revision ID: 331da006773c
Revises: 
Create Date: 2026-06-20 15:02:04.609150

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '331da006773c'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Baseline schema generated from database.py init_db()
    # Note: Using op.execute with raw SQL since we are migrating an existing raw-SQL app to Alembic
    op.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            title TEXT,
            severity TEXT,
            confidence TEXT DEFAULT 'HIGH',
            confidence_score INTEGER DEFAULT 80,
            attack_type TEXT,
            evidence TEXT,
            evidence_citations TEXT,
            attacker_ip TEXT,
            llm_summary TEXT,
            attacker_report TEXT,
            verdict TEXT DEFAULT 'PENDING',
            incident_id INTEGER,
            device_fingerprint TEXT,
            tenant_id TEXT DEFAULT 'default'
        )
    ''')
    op.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            title TEXT,
            severity TEXT,
            status TEXT DEFAULT 'ACTIVE',
            correlation_key TEXT,
            llm_summary TEXT,
            verdict TEXT DEFAULT 'PENDING',
            analyst_notes TEXT,
            resolved_at TIMESTAMP,
            tenant_id TEXT DEFAULT 'default'
        )
    ''')

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS incidents CASCADE;")
    op.execute("DROP TABLE IF EXISTS alerts CASCADE;")
