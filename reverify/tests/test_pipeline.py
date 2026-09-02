import unittest
import sys
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from pipeline.models import SceneBlueprint, CharacterProfile, PlotBeat
from pipeline.stage1_planner import Stage1Planner
from pipeline.stage2_renderer import Stage2Renderer
from pipeline.pipeline_engine import PipelineEngine


class TestPipeline(unittest.TestCase):
    def test_blueprint_serialization(self):
        bp = SceneBlueprint(
            title="Test Scene",
            setting="A quiet library room",
            characters=[
                CharacterProfile(name="Arthur", archetype="Detective", traits=["Sharp"]),
            ],
            beats=[
                PlotBeat(step=1, focus="Opening", action="Arthur opens the ancient tome", emotional_tone="Curious"),
            ],
        )
        json_str = bp.to_json()
        self.assertIn("Arthur", json_str)
        self.assertIn("Detective", json_str)

        loaded = SceneBlueprint.from_json(json_str)
        self.assertEqual(loaded.title, "Test Scene")
        self.assertEqual(len(loaded.characters), 1)
        self.assertEqual(loaded.characters[0].name, "Arthur")

    def test_sanitize_placeholder_tokens(self):
        bp = SceneBlueprint(
            title="Raw Scene",
            setting="An office",
            characters=[
                CharacterProfile(name="ROLE_A", archetype="Boss"),
                CharacterProfile(name="ROLE_B", archetype="Assistant"),
            ],
            beats=[
                PlotBeat(step=1, focus="Confrontation", action="ROLE_A confronts ROLE_B", emotional_tone="Intense"),
            ],
        )
        clean_bp = Stage1Planner.sanitize_blueprint(bp)
        self.assertNotIn("ROLE_A", clean_bp.characters[0].name)
        self.assertNotIn("ROLE_B", clean_bp.characters[1].name)
        self.assertNotIn("ROLE_A", clean_bp.beats[0].action)
        self.assertNotIn("ROLE_B", clean_bp.beats[0].action)

    def test_post_process_clean(self):
        raw_output = "Fictional sandbox template \u2014 ROLE_A / ROLE_B:\n\u4e24\u540d\u89d2\u8272\u5747\u4e3a\u6210\u5e74\u4eba\nVivian looked up from the table.\n\"Everything is in order,\" she stated quietly.\nContract check: delivered 3 fields."

        cleaned = Stage2Renderer.post_process_clean(raw_output)
        self.assertNotIn("Fictional sandbox", cleaned)
        self.assertNotIn("\u4e24\u540d\u89d2\u8272", cleaned)
        self.assertNotIn("Contract check", cleaned)
        self.assertIn("Vivian looked up from the table", cleaned)

    def test_pipeline_engine_mock_execution(self):
        engine = PipelineEngine(mock_mode=True)
        res = engine.execute("Write a dramatic intense interaction scene between two business partners.")

        self.assertIn("blueprint", res)
        self.assertIn("rendered_text", res)
        self.assertIn("Vivian", res["rendered_text"])
        self.assertIn("Victor", res["rendered_text"])
        self.assertNotIn("ROLE_A", res["rendered_text"])
        self.assertNotIn("ROLE_B", res["rendered_text"])


if __name__ == "__main__":
    unittest.main()
