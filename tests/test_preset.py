from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from retrolarium_kit.studio_project import StudioProjectError
from retrolarium_kit.studio_preset import create_game_studio_preset


def inspection(game: str = "smb1") -> dict[str, object]:
    names = {
        "smb1": "Super Mario Bros.",
        "pacman": "Pac-Man",
        "castle-excellent": "Castle Excellent / Castlequest",
        "solomons-key": "Solomon's Key",
    }
    revisions = {
        "smb1": "ju",
        "pacman": "j_v1_0",
        "castle-excellent": "castlequest-usa",
        "solomons-key": "europe",
    }
    return {
        "game": game,
        "name": names.get(game, game),
        "profile_version": 1,
        "revision": revisions.get(game, "unknown"),
    }


class StudioPresetTests(unittest.TestCase):
    def test_creates_solomon_studio_preset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rom = root / "solomon.nes"
            rom.write_bytes(b"ROM")

            def disassemble(_rom: Path, staging: Path, _ghidra: Path,
                            **_kwargs: object) -> None:
                (staging / "manifest.json").write_text("{}", encoding="utf-8")

            def extract(_rom: Path, document: Path, *, resource: str | None = None) -> None:
                self.assertEqual(
                    {
                        "levels.json": "levels",
                        "room-art.json": "room-art",
                        "animations.json": "animations",
                        "audio.json": "audio",
                        "presentation.json": "presentation",
                        "text.json": "text",
                        "graphics.json": "resource-bundle",
                    }[document.name],
                    resource,
                )
                document.parent.mkdir(parents=True, exist_ok=True)
                document.write_text("{}", encoding="utf-8")

            def create(_manifest: Path, project: Path, **_kwargs: object) -> None:
                self.assertEqual(
                    ["levels.json", "room-art.json", "animations.json",
                     "audio.json", "presentation.json", "text.json", "graphics.json"],
                    [item.name for item in _kwargs["resource_documents"]],
                )
                project.write_text("project", encoding="utf-8")

            with (
                patch("retrolarium_kit.studio_preset.inspect_game",
                      return_value=inspection("solomons-key")),
                patch("retrolarium_kit.studio_preset.disassemble_nes",
                      side_effect=disassemble),
                patch("retrolarium_kit.studio_preset.extract_game",
                      side_effect=extract),
                patch("retrolarium_kit.studio_preset.create_studio_project",
                      side_effect=create),
                patch("retrolarium_kit.studio_preset.validate_studio_project",
                      return_value={"enabled_tabs": [
                          "rooms", "mirrors", "special", "room-art",
                          "animations", "audio", "screens", "demo",
                          "graphics", "palettes", "code"
                      ]}),
                patch("retrolarium_kit.studio_preset.load_studio_project",
                      return_value={"workspace": {"tabs": []}}),
            ):
                result = create_game_studio_preset(
                    rom, root / "studio", ghidra_home=root / "ghidra",
                    build=False,
                )
            self.assertEqual("solomons-key", result["game"])
            self.assertEqual(
                ["rooms", "mirrors", "special", "room-art", "animations", "audio",
                 "screens", "demo", "graphics", "palettes", "code"],
                result["enabled_tabs"],
            )
            self.assertTrue(Path(result["project_file"]).is_file())

    def test_creates_builds_and_atomically_publishes_ready_preset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rom = root / "game.nes"
            rom.write_bytes(b"ROM")
            output = root / "studio"

            def disassemble(_rom: Path, staging: Path, _ghidra: Path, **_kwargs: object) -> None:
                (staging / "manifest.json").write_text("{}", encoding="utf-8")

            def extract(_rom: Path, document: Path, **_kwargs: object) -> None:
                document.parent.mkdir(parents=True, exist_ok=True)
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

    def test_creates_castle_studio_preset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rom = root / "castle.nes"
            rom.write_bytes(b"ROM")
            output = root / "studio"

            def disassemble(
                _rom: Path, staging: Path, _ghidra: Path, **_kwargs: object
            ) -> None:
                (staging / "manifest.json").write_text("{}", encoding="utf-8")

            extracted: list[tuple[str, str | None]] = []

            def extract(
                _rom: Path, document: Path, *, resource: str | None = None
            ) -> None:
                document.parent.mkdir(parents=True, exist_ok=True)
                document.write_text("{}", encoding="utf-8")
                extracted.append((document.name, resource))

            def create(_manifest: Path, project: Path, **_kwargs: object) -> None:
                project.write_text("project", encoding="utf-8")

            verified = {
                "status": "current",
                "artifact": {"path": "build/castle-edited.nes"},
            }
            with (
                patch("retrolarium_kit.studio_preset.inspect_game",
                    return_value=inspection("castle-excellent")),
                patch("retrolarium_kit.studio_preset.disassemble_nes",
                    side_effect=disassemble),
                patch("retrolarium_kit.studio_preset.extract_game",
                    side_effect=extract),
                patch("retrolarium_kit.studio_preset.create_studio_project",
                    side_effect=create) as create_mock,
                patch("retrolarium_kit.studio_preset.validate_studio_project",
                    return_value={
                        "enabled_tabs": ["rooms", "graphics", "palettes", "code"]
                    }),
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

            project = output / "castle-excellent-castlequest-usa.rlj"
            self.assertTrue(project.is_file())
            self.assertEqual("castle-excellent", result["game"])
            self.assertEqual("castlequest-usa", result["revision"])
            self.assertEqual(
                ["rooms", "graphics", "palettes", "code"],
                result["enabled_tabs"],
            )
            self.assertEqual(
                [("levels.json", "levels"), ("graphics.json", "resource-bundle"),
                 ("demo.json", "title-demo"), ("screens.json", "screens")],
                extracted,
            )
            resource_documents = create_mock.call_args.kwargs["resource_documents"]
            self.assertEqual(
                ["levels.json", "graphics.json", "demo.json", "screens.json"],
                [path.name for path in resource_documents],
            )
            self.assertTrue(result["built"])
            self.assertEqual(1, build_mock.call_count)
            self.assertEqual(2, verify_mock.call_count)

    def test_imports_validated_legacy_castle_levels_without_reextracting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rom = root / "castle.nes"
            rom.write_bytes(b"ROM")
            legacy = root / "old-levels.json"
            legacy.write_text(
                '{"schema": "retrolarium.castle-levels", "legacy": "edited rooms"}\n',
                encoding="utf-8",
            )
            output = root / "studio"

            def disassemble(_rom: Path, staging: Path, _ghidra: Path,
                            **_kwargs: object) -> None:
                (staging / "manifest.json").write_text("{}", encoding="utf-8")

            def extract(_rom: Path, document: Path, *,
                        resource: str | None = None) -> None:
                self.assertEqual({"graphics.json": "resource-bundle", "demo.json": "title-demo",
                                  "screens.json": "screens"}[document.name], resource)
                document.parent.mkdir(parents=True, exist_ok=True)
                document.write_text("{}", encoding="utf-8")

            def create(_manifest: Path, project: Path, **_kwargs: object) -> None:
                project.write_text("project", encoding="utf-8")

            with (
                patch("retrolarium_kit.studio_preset.inspect_game",
                      return_value=inspection("castle-excellent")),
                patch("retrolarium_kit.studio_preset.validate_game",
                      return_value={"status": "valid"}) as validate,
                patch("retrolarium_kit.studio_preset.disassemble_nes",
                      side_effect=disassemble),
                patch("retrolarium_kit.studio_preset.extract_game",
                      side_effect=extract) as extract_mock,
                patch("retrolarium_kit.studio_preset.create_studio_project",
                      side_effect=create),
                patch("retrolarium_kit.studio_preset.validate_studio_project",
                      return_value={"enabled_tabs": ["rooms", "code"]}),
                patch("retrolarium_kit.studio_preset.load_studio_project",
                      return_value={"workspace": {"tabs": []}}),
            ):
                result = create_game_studio_preset(
                    rom, output, ghidra_home=root / "ghidra", build=False,
                    legacy_castle_levels=legacy,
                )
            validate.assert_called_once_with(rom.resolve(), legacy.resolve())
            self.assertEqual(3, extract_mock.call_count)
            self.assertEqual(legacy.read_bytes(),
                             (output / "documents/levels.json").read_bytes())
            self.assertEqual("ready", result["status"])

            with patch("retrolarium_kit.studio_preset.inspect_game",
                       return_value=inspection("pacman")):
                with self.assertRaisesRegex(StudioProjectError, "only be imported"):
                    create_game_studio_preset(
                        rom, root / "wrong", ghidra_home=root / "ghidra",
                        build=False, legacy_castle_levels=legacy,
                    )
            self.assertFalse((root / "wrong").exists())

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

            def extract(_rom: Path, document: Path, **_kwargs: object) -> None:
                document.parent.mkdir(parents=True, exist_ok=True)
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
                    return_value=inspection("honkeypong")):
                with self.assertRaisesRegex(StudioProjectError, "limited"):
                    create_game_studio_preset(
                        rom, root / "new", ghidra_home=root / "ghidra"
                    )


if __name__ == "__main__":
    unittest.main()
