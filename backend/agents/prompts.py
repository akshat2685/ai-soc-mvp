import os
import logging

logger = logging.getLogger(__name__)

# Map agent identifiers to their specific prompt filenames in the project root
PROMPT_FILES = {
    "supervisor": "SUPERVISOR_PROMPT.md",
    "threat_hunter": "TRIAGE_ANALYST_PROMPT.md",
    "knowledge": "THREAT_INTEL_AGENT_PROMPT.md",
    "root_cause": "DEVSECOPS_AGENT_PROMPT.md",
    "soar": "RESPONSE_COORDINATOR_PROMPT.md",
    "purple_team": "PURPLE_TEAM_ORCHESTRATOR_PROMPT.md",
    "playbook_rl": "PLAYBOOK_RL_OPTIMIZER_PROMPT.md",
}

# Map agent identifiers to their required skill files in the skills/ directory
AGENT_SKILLS = {
    "threat_hunter": ["threat_hunting.md", "malware_analysis.md"],
    "root_cause": ["vulnerability_management.md"],
    "knowledge": ["threat_intelligence.md"],
    "soar": ["incident_response.md"],
    "supervisor": ["coordination.md"],
    "purple_team": ["threat_intelligence.md", "coordination.md"],
    "playbook_rl": ["incident_response.md"],
}

class PromptLoader:
    _cached_constitution = None
    _cached_prompts = {}
    _cached_skills = {}

    @classmethod
    def get_project_root(cls) -> str:
        # Resolves root directory relative to backend/agents/prompts.py
        return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    @classmethod
    def load_constitution(cls) -> str:
        if cls._cached_constitution is not None:
            return cls._cached_constitution

        root = cls.get_project_root()
        const_path = os.path.join(root, "EDYSOR_CONSTITUTION.md")
        
        if os.path.exists(const_path):
            try:
                with open(const_path, "r", encoding="utf-8") as f:
                    cls._cached_constitution = f.read()
                    logger.info("EDYSOR Constitutional Framework v1.0 loaded successfully.")
                    return cls._cached_constitution
            except Exception as e:
                logger.error(f"Failed to read EDYSOR_CONSTITUTION.md: {e}")
        
        # Safe fallback
        cls._cached_constitution = "EDYSOR CONSTITUTIONAL MANDATE: PROTECT > DETECT > RESPOND > LEARN > IMPROVE"
        return cls._cached_constitution

    @classmethod
    def load_agent_skills(cls, agent_name: str) -> str:
        """Loads and combines all skill files assigned to an agent."""
        if agent_name in cls._cached_skills:
            return cls._cached_skills[agent_name]

        required_skills = AGENT_SKILLS.get(agent_name, [])
        if not required_skills:
            return ""

        root = cls.get_project_root()
        skills_dir = os.path.join(root, "skills")
        combined_skills = []

        for skill_file in required_skills:
            skill_path = os.path.join(skills_dir, skill_file)
            if os.path.exists(skill_path):
                try:
                    with open(skill_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        # Extract content without frontmatter if present (basic split)
                        if content.startswith("---"):
                            parts = content.split("---", 2)
                            if len(parts) >= 3:
                                content = parts[2].strip()
                        combined_skills.append(content)
                except Exception as e:
                    logger.error(f"Failed to read skill file {skill_file}: {e}")

        if combined_skills:
            final_skills = "\n\n---\n\n".join(combined_skills)
            skill_block = f"\n\n### AGENT SKILLS & ABILITIES ###\n{final_skills}\n"
            cls._cached_skills[agent_name] = skill_block
            return skill_block

        return ""

    @classmethod
    def get_prompt(cls, agent_name: str, fallback_prompt: str = "") -> str:
        """Returns the prompt for the specified agent, prepended with the constitution and appended with skills."""
        constitution = cls.load_constitution()
        skills_block = cls.load_agent_skills(agent_name)
        
        # Check cache first
        if agent_name in cls._cached_prompts:
            return f"{constitution}\n\n{cls._cached_prompts[agent_name]}{skills_block}"

        filename = PROMPT_FILES.get(agent_name)
        if not filename:
            # If no dedicated file, wrap the fallback prompt
            return f"{constitution}\n\n{fallback_prompt}{skills_block}"

        root = cls.get_project_root()
        path = os.path.join(root, filename)

        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    prompt_content = f.read()
                    cls._cached_prompts[agent_name] = prompt_content
                    logger.info(f"Loaded prompt for agent '{agent_name}' from {filename}.")
                    return f"{constitution}\n\n{prompt_content}{skills_block}"
            except Exception as e:
                logger.error(f"Error reading prompt file {filename}: {e}")

        # Fallback if file read fails or file is missing
        cls._cached_prompts[agent_name] = fallback_prompt
        return f"{constitution}\n\n{fallback_prompt}{skills_block}"
