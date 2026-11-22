from __future__ import annotations

import csv
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_disassembler.containers import (
    BUILD_TIMEOUT,
    ContainerError,
    docker_run_command,
    run_container_build,
)


def mount_fields(command: list[str]) -> list[str]:
    # Docker reads --mount as one CSV record.
    return next(csv.reader([command[command.index("--mount") + 1]]))


class DockerRunCommandTests(unittest.TestCase):
    def test_a_comma_and_a_space_in_the_path_stay_in_the_source_field(self) -> None:
        project = Path("/home/user/my games,old/project")
        command = docker_run_command("retrolarium/ca65", project, ["make", "all"])
        self.assertEqual(["type=bind", f"source={project}", "target=/work"], mount_fields(command))
        self.assertEqual(["--workdir", "/work", "retrolarium/ca65", "make", "all"], command[-5:])
        self.assertEqual(["docker", "run", "--rm"], command[:3])

    def test_a_quote_or_a_line_break_in_the_path_is_refused(self) -> None:
        for project in (Path('/home/user/"quoted"'), Path("/home/user/two\nlines")):
            with self.assertRaisesRegex(ContainerError, "quote or a line break"):
                docker_run_command("image", project, ["make"])

    def test_posix_builds_run_as_the_calling_user(self) -> None:
        project = Path("/work/project")
        with (
            patch("retrolarium_disassembler.containers.os.name", "posix"),
            patch("retrolarium_disassembler.containers.os.getuid", return_value=1234, create=True),
            patch("retrolarium_disassembler.containers.os.getgid", return_value=567, create=True),
        ):
            command = docker_run_command("image", project, ["make"])
        self.assertEqual("1234:567", command[command.index("--user") + 1])

    def test_windows_builds_leave_the_user_to_docker_desktop(self) -> None:
        project = Path("project")
        with patch("retrolarium_disassembler.containers.os.name", "nt"):
            command = docker_run_command("image", project, ["make"])
        self.assertNotIn("--user", command)


class RunContainerBuildTests(unittest.TestCase):
    def test_a_build_out_of_time_removes_its_container(self) -> None:
        calls: list[list[str]] = []

        def run(command: list[str], **options: object):
            calls.append(command)
            if command[:2] == ["docker", "run"]:
                self.assertEqual(BUILD_TIMEOUT, options["timeout"])
                raise subprocess.TimeoutExpired(command, options["timeout"])
            return subprocess.CompletedProcess(command, 0)

        with patch("retrolarium_disassembler.containers.subprocess.run", side_effect=run):
            with self.assertRaisesRegex(ContainerError, "did not finish in 15 minutes"):
                run_container_build("image", Path("project"), ["make"])
        name = calls[0][calls[0].index("--name") + 1]
        self.assertEqual(["docker", "rm", "--force", name], calls[1])

    def pipeline_command(self, build, project: Path, image: str, error: type[BaseException]) -> list[str]:
        commands: list[list[str]] = []

        def run(command: list[str], **options: object):
            commands.append(command)
            self.assertEqual(BUILD_TIMEOUT, options["timeout"])
            return subprocess.CompletedProcess(command, 2)

        with patch("retrolarium_disassembler.containers.subprocess.run", side_effect=run):
            with self.assertRaisesRegex(error, "failed with"):
                build(project, image)
        self.assertEqual(1, len(commands))
        self.assertEqual(["type=bind", f"source={project.resolve()}", "target=/work"], mount_fields(commands[0]))
        return commands[0]

    def test_every_pipeline_builds_through_the_helper(self) -> None:
        from retrolarium_disassembler.megadrive.emit import MegaDriveEmitError
        from retrolarium_disassembler.megadrive.pipeline import _build_emitted_project
        from retrolarium_disassembler.nes.pipeline import PipelineError, build_in_container
        from retrolarium_disassembler.snes.pipeline import SnesPipelineError, build_snes_in_container

        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "a,b c"
            project.mkdir()
            nes = self.pipeline_command(build_in_container, project, "nes-image", PipelineError)
            self.assertEqual(["nes-image", "make", "all"], nes[-3:])
            snes = self.pipeline_command(build_snes_in_container, project, "snes-image", SnesPipelineError)
            self.assertEqual(["snes-image", "make", "all"], snes[-3:])
            megadrive = self.pipeline_command(_build_emitted_project, project, "md-image", MegaDriveEmitError)
            self.assertEqual(["md-image", "sh", "-c"], megadrive[-4:-1])


if __name__ == "__main__":
    unittest.main()
