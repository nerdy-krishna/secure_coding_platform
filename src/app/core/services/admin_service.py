# src/app/core/services/admin_service.py
import logging
import uuid
from typing import List, Optional
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.framework_repo import FrameworkRepository
from app.infrastructure.database.repositories.agent_repo import AgentRepository
from app.infrastructure.database.repositories.prompt_template_repo import (
    PromptTemplateRepository,
)
from app.api.v1 import models as api_models

logger = logging.getLogger(__name__)


class AdminService:
    def __init__(
        self,
        llm_repo: LLMConfigRepository,
        framework_repo: FrameworkRepository,
        agent_repo: AgentRepository,
        prompt_template_repo: PromptTemplateRepository,
    ):
        self.llm_repo = llm_repo
        self.framework_repo = framework_repo
        self.agent_repo = agent_repo
        self.prompt_template_repo = prompt_template_repo

    async def get_all_configs(self) -> List[api_models.LLMConfigurationRead]:
        """Fetches all LLM configurations from the database."""
        logger.info("Fetching all LLM configurations.")
        configs_db = await self.llm_repo.get_all()
        return [api_models.LLMConfigurationRead.from_orm(c) for c in configs_db]

    async def create_config(
        self, config_create: api_models.LLMConfigurationCreate
    ) -> api_models.LLMConfigurationRead:
        """Creates a new LLM configuration."""
        logger.info(
            "Creating new LLM configuration.",
            extra={"name": config_create.name, "provider": config_create.provider},
        )
        config_db = await self.llm_repo.create(config_create)
        return api_models.LLMConfigurationRead.from_orm(config_db)

    async def update_config(
        self, config_id: uuid.UUID, config_update: api_models.LLMConfigurationUpdate
    ) -> Optional[api_models.LLMConfigurationRead]:
        """Updates an existing LLM configuration."""
        logger.info("Updating LLM configuration.", extra={"config_id": str(config_id)})
        updated_db = await self.llm_repo.update(config_id, config_update)
        if updated_db:
            return api_models.LLMConfigurationRead.from_orm(updated_db)
        logger.warning(
            "LLM configuration not found for update.",
            extra={"config_id": str(config_id)},
        )
        return None

    async def delete_config(self, config_id: uuid.UUID) -> bool:
        """Deletes an LLM configuration."""
        logger.info("Deleting LLM configuration.", extra={"config_id": str(config_id)})
        deleted = await self.llm_repo.delete(config_id)
        return deleted is not None

    # --- Framework Methods ---
    async def create_framework(
        self, framework_create: api_models.FrameworkCreate
    ) -> api_models.FrameworkRead:
        """Creates a new framework."""
        logger.info(f"Creating new framework: {framework_create.name}")
        db_framework = await self.framework_repo.create_framework(framework_create)
        return api_models.FrameworkRead.from_orm(db_framework)

    async def get_all_frameworks(self) -> List[api_models.FrameworkRead]:
        """Fetches all frameworks."""
        logger.info("Fetching all frameworks.")
        db_frameworks = await self.framework_repo.get_all_frameworks()
        return [api_models.FrameworkRead.from_orm(f) for f in db_frameworks]

    async def get_framework_by_id(
        self, framework_id: uuid.UUID
    ) -> Optional[api_models.FrameworkRead]:
        """Fetches a single framework by its ID."""
        logger.info(f"Fetching framework by ID: {framework_id}")
        db_framework = await self.framework_repo.get_framework_by_id(framework_id)
        if db_framework:
            return api_models.FrameworkRead.from_orm(db_framework)
        return None

    async def update_framework(
        self, framework_id: uuid.UUID, framework_update: api_models.FrameworkUpdate
    ) -> Optional[api_models.FrameworkRead]:
        """Updates an existing framework."""
        logger.info(f"Updating framework: {framework_id}")
        db_framework = await self.framework_repo.update_framework(
            framework_id, framework_update
        )
        if db_framework:
            return api_models.FrameworkRead.from_orm(db_framework)
        return None

    async def delete_framework(self, framework_id: uuid.UUID) -> bool:
        """Deletes a framework."""
        logger.info(f"Deleting framework: {framework_id}")
        return await self.framework_repo.delete_framework(framework_id)

    # --- Agent Methods ---
    async def create_agent(
        self, agent_create: api_models.AgentCreate
    ) -> api_models.AgentRead:
        """Creates a new agent."""
        logger.info(f"Creating new agent: {agent_create.name}")
        db_agent = await self.agent_repo.create_agent(agent_create)
        return api_models.AgentRead.from_orm(db_agent)

    async def get_all_agents(self) -> List[api_models.AgentRead]:
        """Fetches all agents."""
        logger.info("Fetching all agents.")
        db_agents = await self.agent_repo.get_all_agents()
        return [api_models.AgentRead.from_orm(agent) for agent in db_agents]

    async def get_agent_by_id(
        self, agent_id: uuid.UUID
    ) -> Optional[api_models.AgentRead]:
        """Fetches a single agent by its ID."""
        logger.info(f"Fetching agent by ID: {agent_id}")
        db_agent = await self.agent_repo.get_agent_by_id(agent_id)
        if db_agent:
            return api_models.AgentRead.from_orm(db_agent)
        return None

    async def update_agent(
        self, agent_id: uuid.UUID, agent_update: api_models.AgentUpdate
    ) -> Optional[api_models.AgentRead]:
        """Updates an existing agent."""
        logger.info(f"Updating agent: {agent_id}")
        db_agent = await self.agent_repo.update_agent(agent_id, agent_update)
        if db_agent:
            return api_models.AgentRead.from_orm(db_agent)
        return None

    async def delete_agent(self, agent_id: uuid.UUID) -> bool:
        """Deletes an agent."""
        logger.info(f"Deleting agent: {agent_id}")
        return await self.agent_repo.delete_agent(agent_id)

    # --- Framework-Agent Mapping Methods ---
    async def update_framework_agent_mappings(
        self, framework_id: uuid.UUID, agent_ids: List[uuid.UUID]
    ) -> Optional[api_models.FrameworkRead]:
        """Updates the agent mappings for a specific framework."""
        logger.info(
            f"Updating agent mappings for framework {framework_id} with {len(agent_ids)} agents."
        )
        db_framework = await self.framework_repo.update_agent_mappings_for_framework(
            framework_id, agent_ids
        )
        if db_framework:
            return api_models.FrameworkRead.from_orm(db_framework)
        return None

    # --- Prompt Template Methods ---
    async def create_prompt_template(
        self, template_create: api_models.PromptTemplateCreate
    ) -> api_models.PromptTemplateRead:
        """Creates a new prompt template."""
        logger.info(f"Creating new prompt template: {template_create.name}")
        db_template = await self.prompt_template_repo.create_template(template_create)
        return api_models.PromptTemplateRead.from_orm(db_template)

    async def get_all_prompt_templates(self) -> List[api_models.PromptTemplateRead]:
        """Fetches all prompt templates."""
        logger.info("Fetching all prompt templates.")
        db_templates = await self.prompt_template_repo.get_all_templates()
        return [api_models.PromptTemplateRead.from_orm(t) for t in db_templates]

    async def get_prompt_template_by_id(
        self, template_id: uuid.UUID
    ) -> Optional[api_models.PromptTemplateRead]:
        """Fetches a single prompt template by its ID."""
        logger.info(f"Fetching prompt template by ID: {template_id}")
        db_template = await self.prompt_template_repo.get_template_by_id(template_id)
        if db_template:
            return api_models.PromptTemplateRead.from_orm(db_template)
        return None

    async def update_prompt_template(
        self,
        template_id: uuid.UUID,
        template_update: api_models.PromptTemplateUpdate,
    ) -> Optional[api_models.PromptTemplateRead]:
        """Updates an existing prompt template."""
        logger.info(f"Updating prompt template: {template_id}")
        db_template = await self.prompt_template_repo.update_template(
            template_id, template_update
        )
        if db_template:
            return api_models.PromptTemplateRead.from_orm(db_template)
        return None

    async def delete_prompt_template(self, template_id: uuid.UUID) -> bool:
        """Deletes a prompt template."""
        logger.info(f"Deleting prompt template: {template_id}")
        return await self.prompt_template_repo.delete_template(template_id)