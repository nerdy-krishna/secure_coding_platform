"""Modified llm IDs to utility_llm_config_id, fast_llm_config_id, reasoning_llm_config_id

Revision ID: becc822c0470
Revises: 13e96dcb0fcd
Create Date: 2025-07-19 23:17:13.448905

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'becc822c0470'
down_revision: Union[str, None] = '13e96dcb0fcd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('cwe_details',
    sa.Column('id', sa.String(length=20), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('abstraction', sa.String(length=50), nullable=True),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('rag_document_text', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('cwe_owasp_mappings',
    sa.Column('cwe_id', sa.String(length=20), nullable=False),
    sa.Column('owasp_category_id', sa.String(length=10), nullable=False),
    sa.Column('owasp_category_name', sa.String(length=255), nullable=False),
    sa.Column('owasp_rank', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['cwe_id'], ['cwe_details.id'], ),
    sa.PrimaryKeyConstraint('cwe_id')
    )
    op.alter_column('agents', 'domain_query',
               existing_type=sa.TEXT(),
               type_=postgresql.JSONB(astext_type=sa.Text()),
               existing_nullable=False,
               postgresql_using="jsonb_build_object('keywords', domain_query, 'metadata_filter', '{}'::jsonb)")
    op.add_column('findings', sa.Column('corroborating_agents', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('findings', sa.Column('cvss_score', sa.DECIMAL(precision=3, scale=1), nullable=True))
    op.add_column('findings', sa.Column('cvss_vector', sa.String(length=100), nullable=True))
    op.add_column('findings', sa.Column('is_applied_in_remediation', sa.Boolean(), server_default='false', nullable=False))
    op.drop_column('findings', 'agent_name')
    op.add_column('scans', sa.Column('utility_llm_config_id', sa.UUID(), nullable=True))
    op.add_column('scans', sa.Column('fast_llm_config_id', sa.UUID(), nullable=True))
    op.add_column('scans', sa.Column('reasoning_llm_config_id', sa.UUID(), nullable=True))
    op.drop_constraint('fk_scans_specialized_llm_config_id_llm_configurations', 'scans', type_='foreignkey')
    op.drop_constraint('fk_scans_main_llm_config_id_llm_configurations', 'scans', type_='foreignkey')
    op.create_foreign_key(op.f('fk_scans_fast_llm_config_id_llm_configurations'), 'scans', 'llm_configurations', ['fast_llm_config_id'], ['id'])
    op.create_foreign_key(op.f('fk_scans_utility_llm_config_id_llm_configurations'), 'scans', 'llm_configurations', ['utility_llm_config_id'], ['id'])
    op.create_foreign_key(op.f('fk_scans_reasoning_llm_config_id_llm_configurations'), 'scans', 'llm_configurations', ['reasoning_llm_config_id'], ['id'])
    op.drop_column('scans', 'specialized_llm_config_id')
    op.drop_column('scans', 'main_llm_config_id')
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('scans', sa.Column('main_llm_config_id', sa.UUID(), autoincrement=False, nullable=True))
    op.add_column('scans', sa.Column('specialized_llm_config_id', sa.UUID(), autoincrement=False, nullable=True))
    op.drop_constraint(op.f('fk_scans_reasoning_llm_config_id_llm_configurations'), 'scans', type_='foreignkey')
    op.drop_constraint(op.f('fk_scans_utility_llm_config_id_llm_configurations'), 'scans', type_='foreignkey')
    op.drop_constraint(op.f('fk_scans_fast_llm_config_id_llm_configurations'), 'scans', type_='foreignkey')
    op.create_foreign_key('fk_scans_main_llm_config_id_llm_configurations', 'scans', 'llm_configurations', ['main_llm_config_id'], ['id'])
    op.create_foreign_key('fk_scans_specialized_llm_config_id_llm_configurations', 'scans', 'llm_configurations', ['specialized_llm_config_id'], ['id'])
    op.drop_column('scans', 'reasoning_llm_config_id')
    op.drop_column('scans', 'fast_llm_config_id')
    op.drop_column('scans', 'utility_llm_config_id')
    op.add_column('findings', sa.Column('agent_name', sa.VARCHAR(length=100), autoincrement=False, nullable=True))
    op.drop_column('findings', 'is_applied_in_remediation')
    op.drop_column('findings', 'cvss_vector')
    op.drop_column('findings', 'cvss_score')
    op.drop_column('findings', 'corroborating_agents')
    op.alter_column('agents', 'domain_query',
               existing_type=postgresql.JSONB(astext_type=sa.Text()),
               type_=sa.TEXT(),
               existing_nullable=False,
               postgresql_using="domain_query->>'keywords'")
    op.drop_table('cwe_owasp_mappings')
    op.drop_table('cwe_details')
    # ### end Alembic commands ###
