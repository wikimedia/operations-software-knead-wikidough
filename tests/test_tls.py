"""test_tls.py: Tests Wikidough's TLS protocols and ciphers support.

This runs the following tests to confirm and validate Wikidough's TLS
configuration:

  - minimum version of TLS supported for each service,
  - associated ciphers and their prioritization.

Before we start, a few things to remember for our TLS configuration, as per and
borrowed from `puppet/hieradata/role/common/wikidough.yaml':

  - The DoH frontend supports only TLSv1.3. There is no TLSv1.2 support.
    - The cipher suite order is:
      . TLS_AES_256_GCM_SHA384
      . TLS_CHACHA20_POLY1305_SHA256
      . TLS_AES_128_GCM_SHA256

  - The DoT frontend supports both TLSv1.2 and TLSv1.3.
    - The cipher suite order for TLSv1.2 is:
      . ECDHE-ECDSA-AES256-GCM-SHA384
      . ECDHE-ECDSA-CHACHA20-POLY1305
      . ECDHE-ECDSA-AES128-GCM-SHA256
    - The cipher suite order for TLSv1.3 is the same as the DoH frontend.

A future version of this test should read the settings from the Puppet YAML
file but there is also some value in keeping two different sources of the same
TLS settings.
"""

import socket
import ssl

import pytest

RESOLVER = "malmok.wikimedia.org"


@pytest.fixture(scope='function')
def connection_tls13(port):
    """Establish a TLSv1.3 connection and return the server-supported protocols.

    This is similar to connection_tls12() below with some minor changes such as
    telling the Python client to set the maximum supported TLS version to 1.3,
    which is the default. It is kept separate to support custom settings and to
    keep things easy to understand.
    """
    assert ssl.HAS_TLSv1_3

    conn = ssl.create_default_context()

    with socket.create_connection((RESOLVER, port)) as sock:
        with conn.wrap_socket(sock, server_hostname=RESOLVER) as ssock:
            cipher = ssock.cipher()

    return cipher


@pytest.fixture(scope='function')
def connection_tls12(port, ciphers):
    """Establish a TLSv1.2 connection and return the server-supported protocols.

    While similar to connection_tls13(), this sets the maximum client supported
    version to TLSv1.2.
    """
    assert ssl.HAS_TLSv1_2

    conn = ssl.create_default_context()

    # OP_NO_TLSv1_3 disables TLSv1.3, effectively setting the client's maximum
    # supported version to TLSv1.2.
    conn.options |= ssl.OP_NO_TLSv1_3

    if ciphers is not None:
        conn.set_ciphers(ciphers)

    with socket.create_connection((RESOLVER, port)) as sock:
        try:
            with conn.wrap_socket(sock, server_hostname=RESOLVER) as ssock:
                cipher = ssock.cipher()
        except (ssl.SSLEOFError, OSError):  # OSError: Python 3.7
            cipher = None

    return cipher


@pytest.mark.parametrize(
    ('port, ciphers'),
    [(853, None)],
)
def test_dot_tls12(connection_tls12, port, ciphers):
    """Tests Wikidough's DNS over TLS settings for TLSv1.2.

    Wikidough sets the minimum version of TLS to 1.2 for DoT.
    """
    cipher, protocol, bits = connection_tls12

    assert "TLSv1.2" == protocol
    assert "TLSv1.3" != protocol
    assert "ECDHE-ECDSA-AES256-GCM-SHA384" == cipher

    # DoT frontend supports TLSv1.2.
    assert connection_tls12 is not None


@pytest.mark.parametrize(
    'port, ciphers',
    [(443, None)],
)
def test_doh_tls12(connection_tls12, port, ciphers):
    """Tests Wikidough's DNS over HTTPS settings for TLSv1.2.

    Wikidough sets the minimum version of TLS to 1.3 for its DoH support, so
    clients trying to negotiate a connection with TLSv1.2 should fail.
    """
    # DoH frontend does not support TLSv1.2.
    assert connection_tls12 is None


@pytest.mark.parametrize('port', (853, ))
def test_dot_tls13(connection_tls13, port):
    """Tests Wikidough's DNS over TLS settings for TLSv1.3."""
    cipher, protocol, bits = connection_tls13

    assert "TLSv1.3" == protocol
    assert "TLS_AES_256_GCM_SHA384" == cipher

    assert "TLSv1.2" != protocol
    assert "TLS_CHACHA20_POLY1305_SHA256" != cipher


@pytest.mark.parametrize('port', (443, ))
def test_doh_tls13(connection_tls13, port):
    """Tests Wikidough's DNS over HTTPS settings for TLSv1.3."""
    cipher, protocol, bits = connection_tls13

    assert "TLSv1.3" == protocol
    assert "TLS_AES_256_GCM_SHA384" == cipher

    assert "TLSv1.2" != protocol
    assert "TLS_CHACHA20_POLY1305_SHA256" != cipher


@pytest.mark.parametrize(
    ('port, ciphers'),
    [(853, 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384')],
)
def test_dot_tls12_chacha20_priority(connection_tls12, port, ciphers):
    """Tests Wikidough's dnsdist instance for ChaCha20 prioritization support.

    Support for temporary re-prioritization of ChaCha20 if the client supports
    it is part of our dnsdist instance, added as a patch during the build.

    This test ensures that if a client prioritizes ChaCha20-Poly1305, it
    temporarily overrides the server-side prioritization of cipher suites.

    We only do this for TLSv1.2 as Python 3 does not allow setting the cipher
    suite order for TLSv1.3; see https://bugs.python.org/issue36484. Note that
    this doesn't affect the test though as the protocol does not matter.
    """
    cipher, protocol, bits = connection_tls12

    assert "ECDHE-ECDSA-CHACHA20-POLY1305" == cipher
    assert "ECDHE-ECDSA-AES256-GCM-SHA384" != cipher


@pytest.mark.parametrize(
    ('port, ciphers'),
    [(443, 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384')],
)
def test_doh_tls13_cipher_priority(connection_tls13, port, ciphers):
    """Tests that the server sets the cipher suite order.

    The order of cipher suites is set by the server and in Wikidough's case,
    the order is:
    TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

    This test confirms that the server sets the order of ciphers, overriding
    the preferred list/cipher of the client.
    """
    cipher, protocol, bits = connection_tls13

    assert "TLS_AES_256_GCM_SHA384" == cipher
    assert "TLS_AES_128_GCM_SHA256" != cipher


def test_dot_session_resumption():
    """Test TLSv1.2 session resumption support in Wikidough.

    This test confirms Wikidough's (dnsdist's) support for TLS session
    resumption via session tickets. There is no additional test for TLSv1.3 or
    DoH; Python 3 does not currently support session resumption with TLSv1.3
    and since the same configuration setting applies for DoH, we don't need a
    separate test for that.
    """
    assert ssl.HAS_TLSv1_2

    conn = ssl.create_default_context()
    # https://mail.python.org/pipermail/python-dev/2018-August/154995.html :(
    conn.options |= ssl.OP_NO_TLSv1_3

    # Establish a connection and save the session.
    with socket.create_connection((RESOLVER, 853)) as sock:
        with conn.wrap_socket(sock, server_hostname=RESOLVER) as ssock:
            s_session = ssock.session

    # Re-establish the connection with the saved session and confirm that it
    # works as intended.
    with socket.create_connection((RESOLVER, 853)) as session_sock:
        with conn.wrap_socket(session_sock, server_hostname=RESOLVER,
                              session=s_session) as session_ssock:
            assert session_ssock.session.has_ticket is True
            assert session_ssock.session_reused is True


def test_certificate_cn():
    """Tests the TLS certificate presented by Wikdough to check the fields.

    Currently this only checks if the commonName matches. The certificate
    validity checks are performed by Icinga's check_http and Wikidough's
    monitoring so it doesn't make sense to replicate them here.
    """
    # FIXME: Update this for wikimedia-dns.org.
    cert = {"subject": ((("commonName", RESOLVER),),)}
    assert ssl.match_hostname(cert, RESOLVER) is None

    # We should never use the unified cert for Wikidough.
    with pytest.raises(ssl.SSLCertVerificationError):
        cert_wmf = {"subject": ((("commonName", "*.wikipedia.org"),),)}
        ssl.match_hostname(cert_wmf, RESOLVER)
