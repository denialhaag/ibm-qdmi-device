# Copyright (c) 2026 Munich Quantum Software Company GmbH
# All rights reserved.
#
# Licensed under the Apache License v2.0 with LLVM Exceptions (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://llvm.org/LICENSE.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Verify read connection reuse and retries through the native HTTP transport."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from threading import Barrier, Thread
from typing import TYPE_CHECKING

import pytest
from offline_service import LoopbackHTTPServer, Service

if TYPE_CHECKING:
    from collections.abc import Iterator

    from native_support import Native

pytestmark = pytest.mark.integration


@dataclass
class KeepAliveService(Service):
    """Record connections and optionally interrupt or synchronize reads."""

    exchanges: list[tuple[str, str, int, dict[str, str], bytes]] = field(default_factory=list)
    close_after: str = ""
    silent_close: bool = False
    barrier: Barrier | None = None
    failures: int = 0


@pytest.fixture
def keep_alive() -> Iterator[KeepAliveService]:
    """Yield an HTTP/1.1 service with bounded, joined handler teardown."""
    state = KeepAliveService()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            """Bound idle sockets retained in native thread-local caches."""
            super().setup()
            self.connection.settimeout(0.5)

        def log_message(self, format: str, *args: object) -> None:  # ruff: ignore[builtin-argument-shadowing]
            """Suppress synthetic authentication values."""

        def respond(self, body: bytes) -> None:
            """Record request state and return a framed fixture response."""
            state.exchanges.append((self.command, self.path, self.client_address[1], dict(self.headers), body))
            key = self.path.rsplit("/", 1)[-1]
            status = 200
            data = state.data[key]
            if key == "configuration":
                if state.barrier is not None:
                    state.barrier.wait(timeout=5)
                if state.failures:
                    state.failures -= 1
                    status = 503
            payload = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Set-Cookie", "session=private")
            self.send_header("Retry-After", "0")
            if key == state.close_after:
                if not state.silent_close:
                    self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            """Read backend metadata."""
            self.respond(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

        def do_POST(self) -> None:
            """Accept one synthetic IAM exchange."""
            self.respond(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    with LoopbackHTTPServer(("127.0.0.1", 0), Handler) as server:
        state.url = f"http://127.0.0.1:{server.server_port}"
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield state
        finally:
            server.shutdown()
            thread.join()


def test_reads_reuse_connections_without_request_state(native: Native, keep_alive: KeepAliveService) -> None:
    """Reuse read sockets across sessions while isolating credentials and cookies."""
    for suffix in ("first", "second"):
        before = len(keep_alive.exchanges)
        keep_alive.data["auth"]["access_token"] = suffix
        parameters = {
            **keep_alive.parameters,
            1: suffix,
            999999996: keep_alive.parameters[999999996].replace("instance", suffix),
        }
        with native.session(parameters) as session:
            assert native.init(session) == 0
        for method, _, _, headers, body in keep_alive.exchanges[before:]:
            assert "Cookie" not in headers
            if method == "GET":
                assert headers["Authorization"] == f"Bearer {suffix}"
                assert headers["Service-CRN"] == parameters[999999996]
                assert body == b""
            else:
                assert "Authorization" not in headers
                assert b"apikey=" + suffix.encode() in body
    reads = {port for method, _, port, _, _ in keep_alive.exchanges if method == "GET"}
    posts = [port for method, _, port, _, _ in keep_alive.exchanges if method == "POST"]
    assert len(reads) == 1
    assert len(set(posts)) == 2
    assert reads.isdisjoint(posts)


@pytest.mark.parametrize("silent", [False, True])
def test_closed_read_connection_recovers(native: Native, keep_alive: KeepAliveService, *, silent: bool) -> None:
    """A server-closed read socket neither poisons reads nor gets used for POST."""
    keep_alive.close_after = "configuration"
    keep_alive.silent_close = silent
    for _ in range(2):
        with native.session(keep_alive.parameters) as session:
            assert native.init(session) == 0
    posts = [port for method, _, port, _, _ in keep_alive.exchanges if method == "POST"]
    reads = {port for method, _, port, _, _ in keep_alive.exchanges if method == "GET"}
    assert len(posts) == len(set(posts)) == 2
    assert len(reads) == 3
    assert reads.isdisjoint(posts)


def test_read_caches_allow_concurrent_threads(native: Native, keep_alive: KeepAliveService) -> None:
    """Two blocked requests complete concurrently on separate thread caches."""
    keep_alive.barrier = Barrier(2)

    def initialize() -> None:
        with native.session(keep_alive.parameters) as session:
            assert native.init(session) == 0

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(lambda _: initialize(), range(2)))
    reads = {port for method, _, port, _, _ in keep_alive.exchanges if method == "GET"}
    assert len(reads) == 2


def test_transient_read_retries_over_keep_alive(native: Native, keep_alive: KeepAliveService) -> None:
    """Read recovery preserves a reusable connection and bounded attempts."""
    keep_alive.failures = 2
    with native.session(keep_alive.parameters) as session:
        assert native.init(session) == 0
    assert sum(path.endswith("/configuration") for _, path, _, _, _ in keep_alive.exchanges) == 3
    assert len({port for method, _, port, _, _ in keep_alive.exchanges if method == "GET"}) == 1
