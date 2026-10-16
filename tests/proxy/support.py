"""Test server for the proxy that runs `ProxyRunner`, i.e. the same protocol handler as `ppe serve`."""

from typing import Any

from aiohttp.test_utils import TestServer
from aiohttp.web_runner import BaseRunner

from prompt_privacy.proxy.app import ProxyRunner


class ProxyTestServer(TestServer):
    async def _make_runner(self, **kwargs: Any) -> BaseRunner:
        return ProxyRunner(self.app, **kwargs)
