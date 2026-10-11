"""This repository carries no names or tables taken from games.

The names a game's repository guards (its config/names.json) are checked as
digests by retrolarium_core.name_guard; a literal table needs a reason in
name_guard_tables.txt.
"""

from __future__ import annotations

from pathlib import Path
import unittest

import helpers  # noqa: F401  (src/ on sys.path)

try:
    from retrolarium_core import name_guard
except ImportError:  # a core without the guard
    name_guard = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(name_guard is None, "retrolarium_core has no name guard")
class GameNamesTests(unittest.TestCase):
    def test_no_game_names(self) -> None:
        self.assertEqual([], [f.render() for f in name_guard.check_names(ROOT)])

    def test_no_game_tables(self) -> None:
        self.assertEqual([], [f.render() for f in name_guard.check_tables(ROOT)])


if __name__ == "__main__":
    unittest.main()
