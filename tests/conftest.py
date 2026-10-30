"""Shared pytest fixtures for WiFiStrike's offline unit tests.

All tests here operate on synthetic, in-memory Scapy packets only.
Nothing in this test suite opens a network interface, requires root,
or transmits/receives over the air.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WIFISTRIKE_PATH = REPO_ROOT / "wifistrike.py"


def _load_wifistrike_module():
    """Import wifistrike.py by path.

    The project ships ``wifistrike.py`` at the repo root (installed as the
    extension-less ``/usr/bin/wifistrike`` by install.sh), so it is loaded
    explicitly by path rather than relying on package discovery.
    """
    spec = importlib.util.spec_from_file_location("wifistrike", WIFISTRIKE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["wifistrike"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def wifistrike_module():
    return _load_wifistrike_module()


@pytest.fixture
def ws(wifistrike_module):
    """Fresh-ish handle to the wifistrike module, with global scan state reset.

    wifistrike.py keeps a couple of module-level dicts (``access_points``,
    ``unique_clients``) that scanning functions populate as a side effect.
    Tests that exercise those functions reset them first so tests don't leak
    state into one another.
    """
    wifistrike_module.access_points.clear()
    wifistrike_module.unique_clients.clear()
    wifistrike_module.gateway_mac = None
    return wifistrike_module
