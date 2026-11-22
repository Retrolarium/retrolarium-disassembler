from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_disassembler.toolchain import (
    INSTALL_MARKER,
    DOWNLOAD_TIMEOUT,
    ToolchainError,
    download,
    install_spc700_backend,
    install_snes_backend,
    install_toolchain,
    load_lock,
    safe_extract,
)


class ToolchainTests(unittest.TestCase):
    def test_disassembly_lock_is_complete(self) -> None:
        lock = load_lock()
        self.assertEqual("12.1.3", lock["ghidra"]["version"])
        self.assertEqual(64, len(lock["ghidra"]["sha256"]))
        self.assertEqual(64, len(lock["nes_loader"]["sha256"]))
        self.assertEqual("MIT", lock["snes_backend"]["license"])
        self.assertEqual("65816:LE:24:snes", lock["snes_backend"]["language_id"])
        self.assertEqual(64, len(lock["snes_backend"]["sha256"]))
        self.assertEqual("MIT", lock["spc700_backend"]["license"])
        self.assertEqual("SPC700:LE:16:default", lock["spc700_backend"]["language_id"])
        self.assertEqual(64, len(lock["spc700_backend"]["sha256"]))

    def test_zip_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape.txt", "bad")
            with self.assertRaises(ToolchainError):
                safe_extract(archive, root / "output")

    def test_installs_only_pinned_snes_language_and_license(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = "ghidra-snes-pinned"
            archive = root / "backend.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(
                    f"{source_root}/data/languages/65816.slaspec",
                    "define endian=little;",
                )
                bundle.writestr(
                    f"{source_root}/data/languages/65816.ldefs",
                    'id="65816:LE:24:snes"',
                )
                bundle.writestr(f"{source_root}/LICENSE", "MIT License")
                bundle.writestr(f"{source_root}/src/main/java/UnwantedLoader.java", "loader")
            ghidra = root / "ghidra"
            support = ghidra / "support"
            support.mkdir(parents=True)
            compiler = support / ("sleigh.bat" if sys.platform == "win32" else "sleigh")
            compiler.write_text("compiler", encoding="utf-8")
            expected = {
                "name": "Retrolarium65816",
                "source_directory": source_root,
                "commit": "1" * 40,
                "language_id": "65816:LE:24:snes",
            }

            def compile_language(command: list[str], **_: object):
                Path(command[1]).with_suffix(".sla").write_bytes(b"compiled")
                return type("Result", (), {"returncode": 0, "stdout": "ok"})()

            with patch(
                "retrolarium_disassembler.ghidra.run_launcher",
                side_effect=compile_language,
            ):
                install_snes_backend(ghidra, archive, expected, root / "staging")

            installed = ghidra / "Ghidra" / "Extensions" / "Retrolarium65816"
            self.assertTrue((installed / "data/languages/65816.sla").is_file())
            self.assertEqual(
                "MIT License",
                (installed / "LICENSE.upstream").read_text(encoding="utf-8"),
            )
            self.assertFalse((installed / "src").exists())

    def test_installs_pinned_spc700_language_and_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = "ghidra-spc700-pinned"
            archive = root / "backend.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(
                    f"{source_root}/data/languages/spc700.slaspec",
                    "define endian=little;",
                )
                bundle.writestr(
                    f"{source_root}/data/languages/spc700.ldefs",
                    'id="SPC700:LE:16:default"',
                )
                bundle.writestr(f"{source_root}/LICENSE", "MIT License")
            ghidra = root / "ghidra"
            support = ghidra / "support"
            support.mkdir(parents=True)
            compiler = support / ("sleigh.bat" if sys.platform == "win32" else "sleigh")
            compiler.write_text("compiler", encoding="utf-8")
            expected = {
                "name": "RetrolariumSPC700",
                "source_directory": source_root,
                "commit": "2" * 40,
                "language_id": "SPC700:LE:16:default",
            }

            def compile_language(command: list[str], **_: object):
                Path(command[1]).with_suffix(".sla").write_bytes(b"compiled")
                return type("Result", (), {"returncode": 0, "stdout": "ok"})()

            with patch(
                "retrolarium_disassembler.ghidra.run_launcher",
                side_effect=compile_language,
            ):
                install_spc700_backend(ghidra, archive, expected, root / "staging")

            installed = ghidra / "Ghidra" / "Extensions" / "RetrolariumSPC700"
            manifest = (installed / "Module.manifest").read_text(encoding="utf-8")
            self.assertIn("MODULE NAME: RetrolariumSPC700", manifest)
            self.assertTrue((installed / "data/languages/spc700.sla").is_file())


def _compile_language(command: list[str], **_: object):
    Path(command[1]).with_suffix(".sla").write_bytes(b"compiled")
    return type("Result", (), {"returncode": 0, "stdout": "ok"})()


class ToolchainUpdateTests(unittest.TestCase):
    """install_toolchain against a fake lock whose archives lie in the cache."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.tool_root = self.root / "tools"
        self.cache = self.tool_root / "cache"
        self.cache.mkdir(parents=True)
        self.lock = {
            "schema_version": 1,
            "ghidra": self.ghidra_archive("12.1.3"),
            "nes_loader": self.archive(
                "loader.zip",
                {"GhidraNes/extension.properties": "name=GhidraNes\n"},
                name="GhidraNes",
                version="v1",
                commit="abc",
            ),
            "snes_backend": self.backend_archive("Retrolarium65816", "65816", "65816:LE:24:snes", "1" * 40),
            "spc700_backend": self.backend_archive("RetrolariumSPC700", "spc700", "SPC700:LE:16:default", "2" * 40),
        }

    def tearDown(self) -> None:
        self.directory.cleanup()

    def archive(self, filename: str, members: dict[str, str], **fields: str) -> dict[str, object]:
        path = self.cache / filename
        with zipfile.ZipFile(path, "w") as bundle:
            for member, text in members.items():
                bundle.writestr(member, text)
        data = path.read_bytes()
        return {
            "archive": filename,
            "url": f"https://example.invalid/{filename}",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            **fields,
        }

    def ghidra_archive(self, version: str) -> dict[str, object]:
        root = f"ghidra_{version}_PUBLIC"
        members = {f"{root}/Ghidra/application.properties": f"application.version={version}\n"}
        for name in ("analyzeHeadless", "analyzeHeadless.bat", "sleigh", "sleigh.bat"):
            members[f"{root}/support/{name}"] = "launcher"
        return self.archive(f"ghidra_{version}.zip", members, version=version, install_directory=root)

    def backend_archive(self, name: str, stem: str, language: str, commit: str) -> dict[str, object]:
        source = f"{stem}-{commit}"
        members = {
            f"{source}/data/languages/{stem}.slaspec": "define endian=little;",
            f"{source}/data/languages/{stem}.ldefs": f'id="{language}"',
            f"{source}/LICENSE": "MIT License",
        }
        return self.archive(
            f"{stem}-{commit}.zip",
            members,
            name=name,
            commit=commit,
            language_id=language,
            source_directory=source,
        )

    def install(self, **options: object) -> dict[str, object]:
        with (
            patch("retrolarium_disassembler.toolchain.load_lock", return_value=copy.deepcopy(self.lock)),
            patch("retrolarium_disassembler.ghidra.run_launcher", side_effect=_compile_language),
            patch("urllib.request.urlopen", side_effect=AssertionError("network used")),
        ):
            return install_toolchain(self.tool_root, **options)

    def marker(self, directory: Path) -> dict[str, object]:
        return json.loads((directory / INSTALL_MARKER).read_text(encoding="utf-8"))

    def leftovers(self) -> list[str]:
        names = [path.name for path in self.tool_root.iterdir()]
        names += [path.name for path in (self.tool_root / "ghidra" / "Ghidra" / "Extensions").iterdir()]
        return sorted(name for name in names if ".old-" in name or name.endswith(".new") or "staging" in name)

    def test_a_changed_ghidra_version_reinstalls_and_updates_the_marker(self) -> None:
        first = self.install()
        ghidra_home = self.tool_root / "ghidra"
        self.assertEqual("12.1.3", first["ghidra_version"])
        self.assertEqual("12.1.3", self.marker(ghidra_home)["components"]["ghidra"]["version"])
        (ghidra_home / "stale.txt").write_text("from the old install", encoding="utf-8")

        self.lock["ghidra"] = self.ghidra_archive("12.1.4")
        second = self.install()

        self.assertEqual("ready", second["status"])
        self.assertEqual("12.1.4", second["ghidra_version"])
        self.assertEqual("12.1.4", self.marker(ghidra_home)["components"]["ghidra"]["version"])
        self.assertFalse((ghidra_home / "stale.txt").exists())
        self.assertEqual([], self.leftovers())

    def test_a_changed_backend_commit_rebuilds_only_that_backend(self) -> None:
        self.install()
        ghidra_home = self.tool_root / "ghidra"
        (ghidra_home / "kept.txt").write_text("the same Ghidra", encoding="utf-8")

        self.lock["snes_backend"] = self.backend_archive("Retrolarium65816", "65816", "65816:LE:24:snes", "3" * 40)
        status = self.install()

        self.assertEqual("3" * 40, status["snes_backend_commit"])
        backend = ghidra_home / "Ghidra" / "Extensions" / "Retrolarium65816"
        self.assertEqual("3" * 40, self.marker(backend)["components"]["Retrolarium65816"]["commit"])
        self.assertTrue((ghidra_home / "kept.txt").is_file())
        self.assertEqual([], self.leftovers())

    def test_an_install_without_a_marker_is_replaced_only_on_request(self) -> None:
        self.install()
        ghidra_home = self.tool_root / "ghidra"
        (ghidra_home / INSTALL_MARKER).unlink()
        self.lock["ghidra"] = self.ghidra_archive("12.1.4")

        with self.assertRaisesRegex(ToolchainError, "--reinstall"):
            self.install()
        self.assertFalse((ghidra_home / INSTALL_MARKER).exists())

        status = self.install(reinstall=True)
        self.assertEqual("12.1.4", status["ghidra_version"])
        self.assertEqual("12.1.4", self.marker(ghidra_home)["components"]["ghidra"]["version"])

    def test_a_matching_install_is_kept(self) -> None:
        self.install()
        ghidra_home = self.tool_root / "ghidra"
        (ghidra_home / "kept.txt").write_text("unchanged", encoding="utf-8")
        self.assertEqual("ready", self.install()["status"])
        self.assertTrue((ghidra_home / "kept.txt").is_file())


class DownloadTests(unittest.TestCase):
    def test_a_stalled_download_names_its_url(self) -> None:
        expected = {"archive": "tool.zip", "url": "https://example.invalid/tool.zip", "size": 1, "sha256": "0" * 64}
        with tempfile.TemporaryDirectory() as directory:
            with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")) as urlopen:
                with self.assertRaisesRegex(ToolchainError, "https://example.invalid/tool.zip.*timed out"):
                    download(expected, Path(directory))
            self.assertEqual(DOWNLOAD_TIMEOUT, urlopen.call_args.kwargs["timeout"])
            self.assertEqual([], list(Path(directory).iterdir()))


if __name__ == "__main__":
    unittest.main()
