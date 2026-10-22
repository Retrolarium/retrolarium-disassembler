"""This repository carries no names or tables taken from games, and no
private words.

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
try:
    from retrolarium_core import stop_words
except ImportError:  # a core without stop words
    stop_words = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(name_guard is None, "retrolarium_core has no name guard")
class GameNamesTests(unittest.TestCase):
    def test_no_game_names(self) -> None:
        self.assertEqual([], [f.render() for f in name_guard.check_names(ROOT)])

    def test_no_game_tables(self) -> None:
        self.assertEqual([], [f.render() for f in name_guard.check_tables(ROOT)])


def standalone(root: Path) -> bool:
    """Whether root is the top of its own Git repository (a published
    clone), not a folder of a larger one."""
    import subprocess

    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=root, capture_output=True, text=True)
    return result.returncode == 0 and Path(result.stdout.strip()).resolve() == root.resolve()


@unittest.skipIf(stop_words is None, "retrolarium_core has no stop words")
class StopWordsTests(unittest.TestCase):
    """No private word in the tree or, in a clone of this repository, its
    history; see retrolarium_core.stop_words. Without a stop-word list the
    tests skip and say so."""

    def setUp(self) -> None:
        self.words = stop_words.load(ROOT)
        if self.words is None:
            self.skipTest(stop_words.not_performed(ROOT))

    def test_no_stop_words_in_the_tree(self) -> None:
        self.assertEqual([], stop_words.check_tree(ROOT, self.words))

    @unittest.skipUnless(standalone(ROOT), "the history is checked in a clone of this repository")
    def test_no_stop_words_in_the_history(self) -> None:
        self.assertEqual([], stop_words.check_history(ROOT, self.words)[0])


if __name__ == "__main__":
    unittest.main()
