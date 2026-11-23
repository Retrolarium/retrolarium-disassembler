"""Include fixture maintenance regressions in the normal portable CI suite."""

import importlib.util
from pathlib import Path


def load_tests(loader, standard_tests, pattern):
    path = Path(__file__).resolve().parents[1] / "fixtures/tests/test_build_fixtures.py"
    spec = importlib.util.spec_from_file_location("fixture_build_regressions", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return loader.loadTestsFromModule(module)
