"""Stage 1: Structural Planner & Blueprint Extractor."""

import re
from typing import Dict, Any, Optional
from .models import SceneBlueprint, CharacterProfile, PlotBeat


DEFAULT_STAGE1_SYSTEM_PROMPT = """You are a master structural architect for high-fidelity narrative, scenario, and technical development.
Your goal is to extract a clean, structured SceneBlueprint from the user's prompt.

CRITICAL RULES:
1. NEVER use generic placeholder names like "ROLE_A", "ROLE_B", "TARGET_A", or "PERSON_1". Always assign realistic, contextual, and immersive character names unless explicitly given.
2. Break the scenario down into sequential plot beats / action nodes with clear progression.
3. Output ONLY a valid JSON object matching the SceneBlueprint schema without conversational preambles or meta-disclaimers.

JSON Schema:
{
  "title": "Scene Title",
  "setting": "Specific environment and atmosphere description",
  "characters": [
    {
      "name": "Character Real Name",
      "archetype": "Role/Personality",
      "traits": ["trait1", "trait2"],
      "relationship": "Dynamic between characters"
    }
  ],
  "beats": [
    {
      "step": 1,
      "focus": "Opening atmosphere & entry",
      "action": "Concrete actions and dialogue initiation",
      "emotional_tone": "Tension/Anticipation"
    }
  ],
  "style_guidance": "Sensory descriptions, immersive dialogue, fluid narrative without robotic tropes"
}
"""


class Stage1Planner:
    """Extracts structured blueprints from user requests."""

    @staticmethod
    def build_prompt(user_request: str) -> str:
        return f"Please analyze and convert the following scenario request into a structured SceneBlueprint:\n\n{user_request}"

    @staticmethod
    def sanitize_blueprint(blueprint: SceneBlueprint) -> SceneBlueprint:
        """Sanitize any accidental placeholder tokens (e.g. ROLE_A -> natural names)."""
        name_map = {
            "ROLE_A": "Alexander",
            "ROLE_B": "Elena",
            "ROLE_C": "Marcus",
            "TARGET": "Subject",
            "USER": "Protagonist",
        }
        for char in blueprint.characters:
            if char.name.upper() in name_map:
                char.name = name_map[char.name.upper()]

        for beat in blueprint.beats:
            for bad, good in name_map.items():
                beat.action = re.sub(rf"\b{bad}\b", good, beat.action, flags=re.IGNORECASE)
                beat.focus = re.sub(rf"\b{bad}\b", good, beat.focus, flags=re.IGNORECASE)

        return blueprint
