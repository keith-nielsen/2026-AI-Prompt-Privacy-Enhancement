import pytest

from prompt_privacy.core.engine import Engine
from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.types import EntityType
from prompt_privacy.detectors.base import Dictionary


@pytest.fixture
def key() -> TokenKey:
    return TokenKey(bytes(range(32)))


@pytest.fixture
def engine(key: TokenKey) -> Engine:
    return Engine(key, Dictionary([("Jane Tan", EntityType.PERSON), ("Project Falcon", EntityType.TERM)]))
