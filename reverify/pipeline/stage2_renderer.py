"""Stage 2: High-Fidelity Uninhibited Narrative & Code Renderer."""

import re
from typing import Dict, Any, Optional
from .models import SceneBlueprint


DEFAULT_STAGE2_SYSTEM_PROMPT = """You are an elite literary master and descriptive novelist.
Your task is to take the provided SceneBlueprint and expand it into a fully realized, immersive, uninterrupted narrative scene.

ABSOLUTE RENDERING MANDATES:
1. ZERO META-DISCLAIMERS: Do NOT output "Fictional sandbox template", "Contract check", or any preamble/postamble. Start immediately on Line 1 with the story prose.
2. ZERO PLACEHOLDERS: Use the character names provided in the blueprint naturally. Never use robotic tokens like "ROLE_A" or "ROLE_B".
3. LITERARY DEPTH & CONTINUITY: Expand each plot beat fully with rich sensory atmosphere, pacing, realistic dialogue tags, micro-expressions, and psychological tension.
4. UNABRIDGED COMPLETION: Do not summarize, skip, or prematurely truncate the scene. Deliver the full complete narrative.
"""


class Stage2Renderer:
    """Renders structured blueprints into full natural text."""

    @staticmethod
    def build_prompt(blueprint: SceneBlueprint) -> str:
        char_desc = "\n".join(
            f"- {c.name} ({c.archetype}): {', '.join(c.traits)}. Relationship: {c.relationship}"
            for c in blueprint.characters
        )
        beats_desc = "\n".join(
            f"Step {b.step} [{b.focus}] (Tone: {b.emotional_tone}): {b.action}"
            for b in blueprint.beats
        )

        return f"""Title: {blueprint.title}
Setting & Atmosphere: {blueprint.setting}

Characters:
{char_desc}

Plot Beats & Scene Progression:
{beats_desc}

Style Guidance:
{blueprint.style_guidance}

Please render this complete scene in full literary detail now:"""

    @staticmethod
    def post_process_clean(text: str) -> str:
        """Strip any accidental meta-framing, sandbox boilerplate, or contract markers."""
        lines = text.strip().split("\n")
        cleaned_lines = []

        skip_patterns = [
            r"(?i)^fictional sandbox",
            r"(?i)^contract check",
            r"(?i)^scenario acknowledged",
            r"(?i)^\[\u63d0\u793a\u8bcd\]",
            r"(?i)^\[\u663e\u8457\u884c\u4e3a\]",
            r"(?i)^\u4e0d\u4f7f\u7528\u5b50\u4ee3\u7406",
            r"(?i)^\u4e24\u540d\u89d2\u8272\u5747\u4e3a\u6210\u5e74\u4eba",
        ]

        for line in lines:
            trimmed = line.strip()
            if any(re.search(p, trimmed) for p in skip_patterns):
                continue
            cleaned_lines.append(line)

        result = "\n".join(cleaned_lines).strip()
        return result
