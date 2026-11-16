import importlib


def test_package_imports() -> None:
    """The package is importable from src/ via the pytest pythonpath setting."""
    module = importlib.import_module("sentinel_detections")
    assert module.__name__ == "sentinel_detections"
