"""Shared pytest session setup."""
import os
from pathlib import Path


def pytest_configure(config):
    # pytest.ini sets --basetemp=.pytest-tmp/run. pytest creates the "run" folder but not its parent,
    # and .pytest-tmp/ is git-ignored, so a fresh checkout failed every tmp_path test at setup.
    # Create the parent here so the suite runs without any pre-existing folder.
    basetemp = getattr(config.option, "basetemp", None)
    if basetemp:
        Path(os.path.abspath(str(basetemp))).parent.mkdir(parents=True, exist_ok=True)
