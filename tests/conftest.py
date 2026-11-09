"""Make the HA-free strx package importable without Home Assistant, run tests/ha only with the HA test harness."""

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "custom_components" / "simarine_strx"))

HA_HARNESS = importlib.util.find_spec("pytest_homeassistant_custom_component") is not None
if not HA_HARNESS:
    collect_ignore = ["ha"]


def pytest_report_header(config):
    if not HA_HARNESS:
        return "tests/ha skipped: pytest-homeassistant-custom-component is not installed (requirements_test.txt)"
    return None
