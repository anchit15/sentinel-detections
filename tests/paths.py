"""Repository paths shared by the tests."""

from pathlib import Path

REPO_ROOT = Path(__file__).parents[1]
RULES_DIR = REPO_ROOT / "rules"
CASES_DIR = REPO_ROOT / "tests" / "cases"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
MANIFEST = REPO_ROOT / "data" / "manifest.yaml"
