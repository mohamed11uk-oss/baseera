import os
import tempfile

os.environ["BASEERA_MODE"] = "offline"
os.environ["BASEERA_DOTENV"] = "off"  # never load the developer's local .env (keys) in tests
os.environ["SOURCE_FEEDS"] = "off"  # never read a locally refreshed feed DB in tests (determinism)
os.environ["BASEERA_CACHE_DIR"] = tempfile.mkdtemp(prefix="baseera-test-cache-")

import pytest  # noqa: E402

from baseera.analyze import Analyzer  # noqa: E402
from baseera.config import Settings  # noqa: E402
from baseera.registry import default_registry  # noqa: E402


@pytest.fixture(scope="session")
def reg():
    return default_registry()


@pytest.fixture(scope="session")
def an(reg):
    s = Settings()
    s.mode = "offline"
    return Analyzer(settings=s, registry=reg, feed={"enbd-unblock.top"})
