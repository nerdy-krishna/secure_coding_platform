"""add llm configs and frameworks to scan table

Revision ID: 324ddaa57c13
Revises: 65a2c5bd9ce3
Create Date: 2025-07-07 23:32:53.663094

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '324ddaa57c13'
down_revision: Union[str, None] = '65a2c5bd9ce3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('scans', sa.Column('main_llm_config_id', sa.UUID(), nullable=True))
    op.add_column('scans', sa.Column('specialized_llm_config_id', sa.UUID(), nullable=True))
    op.add_column('scans', sa.Column('frameworks', postgresql.JSONB(), nullable=True))
    
    # Assign explicit names to foreign keys
    op.create_foreign_key('fk_scans_main_llm_config_id', 'scans', 'llm_configurations', ['main_llm_config_id'], ['id'])
    op.create_foreign_key('fk_scans_specialized_llm_config_id', 'scans', 'llm_configurations', ['specialized_llm_config_id'], ['id'])
    op.create_foreign_key('fk_chat_sessions_project_id', 'chat_sessions', 'projects', ['project_id'], ['id'])
    
    # The alter_column calls are typically fine as generated
    op.alter_column('llm_configurations', 'encrypted_api_key',
               existing_type=sa.VARCHAR(),
               type_=sa.Text(),
               existing_nullable=False)
    op.alter_column('llm_configurations', 'input_cost_per_million',
               existing_type=sa.NUMERIC(precision=10, scale=6),
               comment=None,
               existing_comment='Cost per 1 million input tokens in USD.',
               existing_nullable=False,
               existing_server_default=sa.text('0.000000'))
    op.alter_column('llm_configurations', 'output_cost_per_million',
               existing_type=sa.NUMERIC(precision=10, scale=6),
               comment=None,
               existing_comment='Cost per 1 million output tokens in USD.',
               existing_nullable=False,
               existing_server_default=sa.text('0.000000'))
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    # Use the same explicit names to drop the constraints
    op.drop_constraint('fk_chat_sessions_project_id', 'chat_sessions', type_='foreignkey')
    op.drop_constraint('fk_scans_specialized_llm_config_id', 'scans', type_='foreignkey')
    op.drop_constraint('fk_scans_main_llm_config_id', 'scans', type_='foreignkey')
    
    op.drop_column('scans', 'frameworks')
    op.drop_column('scans', 'specialized_llm_config_id')
    op.drop_column('scans', 'main_llm_config_id')
    
    # The alter_column calls are typically fine as generated
    op.alter_column('llm_configurations', 'output_cost_per_million',
               existing_type=sa.NUMERIC(precision=10, scale=6),
               comment='Cost per 1 million output tokens in USD.',
               existing_nullable=False,
               existing_server_default=sa.text('0.000000'))
    op.alter_column('llm_configurations', 'input_cost_per_million',
               existing_type=sa.NUMERIC(precision=10, scale=6),
               comment='Cost per 1 million input tokens in USD.',
               existing_nullable=False,
               existing_server_default=sa.text('0.000000'))
    op.alter_column('llm_configurations', 'encrypted_api_key',
               existing_type=sa.Text(),
               type_=sa.VARCHAR(),
               existing_nullable=False)
    # ### end Alembic commands ###