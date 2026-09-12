from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from retrolarium_kit.studio_project import StudioProjectError
from retrolarium_kit.studio_preset import create_game_studio_preset


def inspection(game: str = "smb1") -> dict[str, object]:
    return {
        "game": game,
        "name": "Super Mario Bros." if game == "smb1" else "Pac-Man",
        "profile_version": 1,
        "revision": "ju" if game == "smb1" else "j_v1_0",
    }


class StudioPresetTests(unittest.TestCase):
    def test_creates_builds_and_atomically_publishes_ready_preset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rom = root / "game.nes"
            rom.write_bytes(b"ROM")
            output = root / "studio"

            def disassemble(_rom: Path, staging: Path, _ghidra: Path, **_kwargs: object) -> None:
                (staging / "manifest.json").write_text("{}", encoding="utf-8")

            def extract(_rom: Path, document: Path) -> None:
                document.parent.mkdir(parents=True)
                document.write_text("{}", encoding="utf-8")

            def create(_manifest: Path, project: Path, **_kwargs: object) -> None:
                project.write_text("project", encoding="utf-8")

            verified = {
                "status": "current",
                "artifact": {"path": "build/smb1-ju-edited.nes"},
            }
            with (
                patch("retrolarium_kit.studio_preset.inspect_game",
                    return_value=inspection()),
                patch("retrolarium_kit.studio_preset.disassemble_nes",
                    side_effect=disassemble),
                patch("retrolarium_kit.studio_preset.extract_game",
                    side_effect=extract),
                patch("retrolarium_kit.studio_preset.create_studio_project",
                    side_effect=create) as create_mock,
                patch("retrolarium_kit.studio_preset.validate_studio_project",
                    return_value={"enabled_tabs": ["world", "levels", "code"]}),
                patch("retrolarium_kit.studio_preset.build_studio_project",
                    return_value={"status": "built"}) as build_mock,
                patch("retrolarium_kit.studio_preset.verify_studio_project",
                    return_value=verified) as verify_mock,
                patch("retrolarium_kit.studio_preset.load_studio_project",
                    return_value={"workspace": {"tabs": []}}),
            ):
                result = create_game_studio_preset(
                    rom, output, ghidra_home=root / "ghidra"
                )

            project = output / "smb1-ju.rlj"
            self.assertTrue(project.is_file())
            self.assertEqual("ready", result["status"])
            self.assertEqual(str(project), result["project_file"])
            self.assertEqual(["world", "levels", "code"], result["enabled_tabs"])
            self.assertTrue(result["built"])
            self.assertEqual(1, create_mock.call_count)
            self.assertEqual(1, build_mock.call_count)
            self.assertEqual(2, verify_mock.call_count)
            self.assertEqual([], list(root.glob(".studio.rlj-stage-*")))

    def test_failure_removes_staging_without_publishing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rom = root / "game.nes"
            rom.write_bytes(b"ROM")
            output = root / "studio"

            def fail(_rom: Path, staging: Path, _ghidra: Path, **_kwargs: object) -> None:
                (staging / "partial.txt").write_text("partial", encoding="utf-8")
                raise OSError("analysis failed")

            with (
                patch("retrolarium_kit.studio_preset.inspect_game",
                    return_value=inspection("pacman")),
                patch("retrolarium_kit.studio_preset.disassemble_nes",
                    side_effect=fail),
            ):
                with self.assertRaisesRegex(OSError, "analysis failed"):
                    create_game_studio_preset(
                        rom, output, ghidra_home=root / "ghidra"
                    )

            self.assertFalse(output.exists())
            self.assertEqual([], list(root.glob(".studio.rlj-stage-*")))

    def test_relocation_validation_failure_retracts_published_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rom = root / "game.nes"
            rom.write_bytes(b"ROM")
            output = root / "studio"

            def disassemble(
                _rom: Path, staging: Path, _ghidra: Path, **_kwargs: object
            ) -> None:
                (staging / "manifest.json").write_text("{}", encoding="utf-8")

            def extract(_rom: Path, document: Path) -> None:
                document.parent.mkdir(parents=True)
                document.write_text("{}", encoding="utf-8")

            def create(_manifest: Path, project: Path, **_kwargs: object) -> None:
                project.write_text("project", encoding="utf-8")

            with (
                patch("retrolarium_kit.studio_preset.inspect_game",
                    return_value=inspection()),
                patch("retrolarium_kit.studio_preset.disassemble_nes",
                    side_effect=disassemble),
                patch("retrolarium_kit.studio_preset.extract_game",
                    side_effect=extract),
                patch("retrolarium_kit.studio_preset.create_studio_project",
                    side_effect=create),
                patch("retrolarium_kit.studio_preset.validate_studio_project",
                    return_value={"enabled_tabs": ["world"]}),
                patch("retrolarium_kit.studio_preset.load_studio_project",
                    side_effect=StudioProjectError("relocation failed")),
            ):
                with self.assertRaisesRegex(StudioProjectError, "relocation failed"):
                    create_game_studio_preset(
                        rom, output, ghidra_home=root / "ghidra", build=False
                    )

            self.assertFalse(output.exists())
            self.assertEqual([], list(root.glob(".studio.rlj-stage-*")))

    def test_rejects_unsupported_game_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rom = root / "game.nes"
            rom.write_bytes(b"ROM")
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(StudioProjectError, "already exists"):
                create_game_studio_preset(
                    rom, existing, ghidra_home=root / "ghidra"
                )

            with patch("retrolarium_kit.studio_preset.inspect_game",
                    return_value=inspection("castle")):
                with self.assertRaisesRegex(StudioProjectError, "limited"):
                    create_game_studio_preset(
                        rom, root / "new", ghidra_home=root / "ghidra"
                    )


if __name__ == "__main__":
    unittest.main()
