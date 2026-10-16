"""Model root-owned test files without requiring an elevated test runner."""
from types import SimpleNamespace

import pytest


@pytest.fixture
def root_path(tmp_path):
    class RootPath(type(tmp_path)):
        def stat(self, *args, **kwargs):
            value = super().stat(*args, **kwargs)
            return SimpleNamespace(**{name: 0 if name == 'st_uid' else getattr(value, name)
                                      for name in dir(value) if name.startswith('st_')})

    return RootPath
