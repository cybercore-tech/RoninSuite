import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch):
    """Point RONIN_HOME at a throwaway dir so tests never touch real data."""
    d = tempfile.mkdtemp(prefix="ronin-test-")
    monkeypatch.setenv("RONIN_HOME", d)
    from ronin import config

    config.paths.cache_clear()
    yield d
    config.paths.cache_clear()


DATA = os.path.join(os.path.dirname(__file__), "data")
