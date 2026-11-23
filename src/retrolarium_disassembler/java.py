"""Validate a JDK before downloads or a noninteractive Ghidra launch."""

import os
from pathlib import Path
import re
import shutil
import subprocess


class JavaError(RuntimeError):
    """Ghidra needs a usable Java development kit."""


def java_environment(ghidra_home: Path | None = None) -> dict[str, str]:
    environment = dict(os.environ)
    homes: list[Path] = []
    if ghidra_home is not None:
        properties = ghidra_home / "support/launch.properties"
        if properties.is_file():
            for raw in properties.read_text(encoding="utf-8").splitlines():
                key, separator, value = raw.partition("=")
                if separator and key.strip() == "JAVA_HOME_OVERRIDE" and value.strip():
                    homes.append(Path(value.strip()))
    if environment.get("JAVA_HOME"):
        homes.append(Path(environment["JAVA_HOME"]))
    found = shutil.which("java")
    if found:
        homes.append(Path(found).resolve().parent.parent)
    suffix = ".exe" if os.name == "nt" else ""
    failures = []
    for home in dict.fromkeys(homes):
        try:
            for tool in ("java", "javac"):
                executable = home / "bin" / (tool + suffix)
                if not executable.is_file():
                    raise JavaError(f"{executable} is missing")
                result = subprocess.run(
                    [str(executable), "-version"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                )
                output = result.stdout + result.stderr
                match = re.search(r'(?:version\s+"|javac\s+)(\d+)', output)
                if result.returncode or match is None or int(match.group(1)) < 21:
                    raise JavaError(f"{executable} is not JDK 21 or later: {output.strip()}")
            environment["JAVA_HOME"] = str(home)
            environment["PATH"] = str(home / "bin") + os.pathsep + environment.get("PATH", "")
            return environment
        except (OSError, subprocess.TimeoutExpired, JavaError) as error:
            failures.append(str(error))
    detail = "; ".join(failures) if failures else "java was not found on PATH or in JAVA_HOME"
    raise JavaError(f"Ghidra needs JDK 21 or later (java and javac). Install a JDK and set JAVA_HOME. {detail}")
