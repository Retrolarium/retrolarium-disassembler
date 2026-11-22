"""docker run for the container builds of emitted projects."""

from __future__ import annotations

from collections.abc import Sequence
import os
from pathlib import Path
import subprocess
import uuid


# A container build that has not ended in this long has hung.
BUILD_TIMEOUT = 15 * 60


class ContainerError(RuntimeError):
    """A container build could not be started or did not end in time."""


def docker_run_command(
    image: str,
    project: Path,
    argv: Sequence[str],
    *,
    workdir: str = "/work",
    name: str | None = None,
) -> list[str]:
    """The docker run line that mounts project at workdir and runs argv there.
    On POSIX the build runs as the calling user, so its outputs are not
    root-owned."""
    source = str(project)
    if '"' in source or "\n" in source or "\r" in source:
        raise ContainerError(f"Docker cannot mount a folder whose path holds a quote or a line break: {source}")
    # --mount takes a CSV list: the quoted field keeps a comma in the path.
    mount = f'type=bind,"source={source}",target={workdir}'
    command = ["docker", "run", "--rm"]
    if name is not None:
        command += ["--name", name]
    if os.name != "nt":
        command += ["--user", f"{os.getuid()}:{os.getgid()}"]
    return [*command, "--mount", mount, "--workdir", workdir, image, *argv]


def run_container_build(image: str, project: Path, argv: Sequence[str], *, timeout: float = BUILD_TIMEOUT) -> int:
    """Run argv in image over project and return its exit code. A build out of
    time is removed with its container: stopping the docker client alone
    would leave the container running."""
    name = f"retrolarium-build-{uuid.uuid4().hex}"
    command = docker_run_command(image, project.resolve(), argv, name=name)
    try:
        return subprocess.run(command, text=True, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=60)
        raise ContainerError(
            f"the container build in {project} did not finish in {int(timeout // 60)} minutes"
        ) from None
