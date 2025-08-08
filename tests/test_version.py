from pathlib import Path

import pytest
from git import Repo
from git.exc import InvalidGitRepositoryError

from boto3_session import __version__


def test_version() -> None:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib

    with Path(Path(__file__).parents[1] / 'pyproject.toml').open('rb') as f:
        version = tomllib.load(f)['project']['version']
    assert version == __version__


def test_tag() -> None:
    try:
        repo = Repo(Path(__file__).parents[1])
    except InvalidGitRepositoryError:
        pytest.skip('Not a git repo.')
    latest_tag = repo.tags[-1]
    assert latest_tag.name == 'v' + __version__
