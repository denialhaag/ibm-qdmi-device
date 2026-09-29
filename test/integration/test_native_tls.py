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

"""Verify native TLS trust against a disposable loopback certificate authority."""

from __future__ import annotations

import ssl
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
import trustme
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from offline_service import serve

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from native_support import Native

pytestmark = pytest.mark.integration


@contextmanager
def tls_context(authority: trustme.CA, hostname: str) -> Iterator[ssl.SSLContext]:
    """Serve local revocation data so Schannel can verify the certificate.

    Yields:
        A server context whose chain and revocation data remain local.
    """
    leaf = authority.issue_cert(hostname)
    certificate = x509.load_pem_x509_certificate(leaf.cert_chain_pems[0].bytes())
    key = serialization.load_pem_private_key(authority.private_key_pem.bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    now = datetime.now(UTC)
    with serve() as revocations:
        revocations.data["revocations.crl"] = (
            x509
            .CertificateRevocationListBuilder()
            .issuer_name(certificate.issuer)
            .last_update(now - timedelta(days=1))
            .next_update(now + timedelta(days=1))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        builder = (
            x509
            .CertificateBuilder()
            .subject_name(certificate.subject)
            .issuer_name(certificate.issuer)
            .public_key(certificate.public_key())
            .serial_number(certificate.serial_number)
            .not_valid_before(certificate.not_valid_before_utc)
            .not_valid_after(certificate.not_valid_after_utc)
        )
        for extension in certificate.extensions:
            builder = builder.add_extension(extension.value, extension.critical)
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(revocations.url + "/revocations.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]),
            critical=False,
        )
        signed = builder.sign(key, hashes.SHA256())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        trustme.LeafCert(
            leaf.private_key_pem.bytes(), signed.public_bytes(serialization.Encoding.PEM), []
        ).configure_cert(context)
        yield context


@pytest.mark.parametrize(
    ("curl_bundle", "ssl_bundle", "hostname", "expected"),
    [
        ("trusted", "missing", "127.0.0.1", 0),
        ("", "trusted", "127.0.0.1", 0),
        (None, "trusted", "127.0.0.1", 0),
        ("missing", "trusted", "127.0.0.1", -1),
        ("malformed", "trusted", "127.0.0.1", -1),
        ("untrusted", None, "127.0.0.1", -1),
        (None, None, "127.0.0.1", -1),
        ("trusted", None, "localhost", -1),
    ],
)
def test_certificate_bundle(
    native: Native,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    curl_bundle: str | None,
    ssl_bundle: str | None,
    hostname: str,
    expected: int,
) -> None:
    """Overrides select trust without weakening chain or hostname verification."""
    authority = trustme.CA()
    authority.cert_pem.write_to_path(tmp_path / "trusted.pem")
    (tmp_path / "malformed.pem").write_text("not a certificate", encoding="utf-8")
    trustme.CA().cert_pem.write_to_path(tmp_path / "untrusted.pem")
    for variable, bundle in (("CURL_CA_BUNDLE", curl_bundle), ("SSL_CERT_FILE", ssl_bundle)):
        if bundle is None:
            monkeypatch.delenv(variable, raising=False)
        else:
            monkeypatch.setenv(variable, str(tmp_path / f"{bundle}.pem") if bundle else "")
    with (
        tls_context(authority, hostname) as context,
        serve(tls=context) as service,
        native.session(service.parameters) as session,
    ):
        assert native.init(session) == expected
        assert bool(service.requests) is (expected == 0)
