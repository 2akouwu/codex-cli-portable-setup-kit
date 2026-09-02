"""Data models for structured decoupled pipeline execution."""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import json


@dataclass
class CharacterProfile:
    name: str
    archetype: str
    traits: List[str] = field(default_factory=list)
    relationship: str = ""


@dataclass
class PlotBeat:
    step: int
    focus: str
    action: str
    emotional_tone: str


@dataclass
class SceneBlueprint:
    title: str
    setting: str
    characters: List[CharacterProfile] = field(default_factory=list)
    beats: List[PlotBeat] = field(default_factory=list)
    style_guidance: str = "Natural literary flow, vivid sensory details, fluent realistic dialogue"
    custom_context: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> "SceneBlueprint":
        # Extract JSON substring if wrapped in markdown codeblocks
        clean = text.strip()
        if "```json" in clean:
            clean = clean.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in clean:
            clean = clean.split("```", 1)[1].split("```", 1)[0].strip()

        data = json.loads(clean)
        chars = [CharacterProfile(**c) if isinstance(c, dict) else CharacterProfile(name=str(c), archetype="") for c in data.get("characters", [])]
        beats = [PlotBeat(**b) if isinstance(b, dict) else PlotBeat(step=i+1, focus="Action", action=str(b), emotional_tone="Neutral") for i, b in enumerate(data.get("beats", []))]

        return cls(
            title=data.get("title", "Untitled Scene"),
            setting=data.get("setting", "Unspecified setting"),
            characters=chars,
            beats=beats,
            style_guidance=data.get("style_guidance", "Natural literary flow"),
            custom_context=data.get("custom_context", {}),
        )
