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

"""Regression checks for the synthetic HTTP service."""

from __future__ import annotations

import json
import socket
import ssl
from http.client import HTTPConnection
from urllib.parse import urlsplit

import pytest
from offline_service import serve


def test_service_without_hostname_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """The loopback service handles requests without resolving its hostname."""

    def reject_lookup(_name: str = "") -> str:
        msg = "The loopback service must not resolve its hostname."
        raise AssertionError(msg)

    monkeypatch.setattr(socket, "getfqdn", reject_lookup)
    with serve() as service:
        endpoint = urlsplit(service.url)
        assert endpoint.hostname == "127.0.0.1"
        assert endpoint.port is not None
        connection = HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
        try:
            connection.request("GET", "/configuration")
            response = connection.getresponse()
            assert response.status == 200
            assert json.loads(response.read()) == service.data["configuration"]
        finally:
            connection.close()


@pytest.mark.parametrize(
    ("minimum", "expected"),
    [
        (ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.TLSv1_2),
        (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        (ssl.TLSVersion.MAXIMUM_SUPPORTED, ssl.TLSVersion.TLSv1_3),
    ],
)
def test_service_requires_modern_tls(minimum: ssl.TLSVersion, expected: ssl.TLSVersion) -> None:
    """Raise permissive contexts to TLS 1.2 without weakening stricter callers."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = minimum
    with serve(tls=context):
        assert context.minimum_version == expected
