"""test_dns.py: Tests Wikidough's DNS over HTTPS and DNS over TLS support.

This runs the following tests to confirm and validate Wikidough's DNS over
HTTPS and DNS over TLS support:

  - DoH and DoT endpoints for secure DNS lookup,
  - the (limited) EDNS Client Subnet (ECS) support for queries to WMF
    authoritative nameservers.

These tests help confirm our intended design of Wikidough against its
deployment by validating the configuration settings for the two Wikidough
components: the dnsdist frontend and the PowerDNS Recursor backend, and how
they interact with each other.
"""

import base64

import dns.message
import dns.query

import pytest

import requests

RESOLVER_URL = "https://wikimedia-dns.org"  # /dns-query where required.
RESOLVER_IP = "185.71.138.138"

ULSFO_IP = "198.35.26.96"
CODFW_IP = "208.80.154.224"

EXAMPLE_ORG_IP = "93.184.216.34"
WESTCOAST_CANADA_IP = "24.64.64.1"
EASTCOAST_CANADA_IP = "206.108.0.1"


def get_rrset(query, record_type=dns.rdatatype.A):
    """Get the RRset from a query response corresponding to the record type.

    Returns a text (string) version of the desired record.
    """
    return query.get_rrset(query.answer, query.question[0].name,
                           dns.rdataclass.IN, rdtype=record_type)[0].to_text()


@pytest.fixture(scope='function')
def make_message(host, record_type):
    """Construct a dns.message object to query for a given record type."""
    if record_type is None:
        record_type = dns.rdatatype.A

    return dns.message.make_query(host, record_type)


@pytest.fixture(scope='function')
def make_message_edns(host, ip, record_type, dnssec):
    """Construct a dns.message with EDNS Client Subnet (ECS) enabled.

    Wikidough enables ECS but _only_ for queries to WMF's authoritative
    nameservers. This is achieved with the following configuration: for
    dnsdist, `useClientSubnet` is enabled for the backend. For the backend
    PowerDNS recursor, `edns-subnet-whitelist` is enabled and is set to the
    list of WMF auth servers (208.80.154.238, 208.80.153.231, 91.198.174.239).

    Wikidough therefore only sends the client IP address (truncated) to WMF
    authoritative nameservers; queries to other nameservers should not have ECS
    enabled for privacy reasons and that is confirmed by a separate test below,
    test_dot_edns_query_no_wikimedia().
    """
    ecs_option = dns.edns.ECSOption(address=ip)

    if record_type is None:
        record_type = dns.rdatatype.A

    return dns.message.make_query(host, rdtype=record_type, use_edns=True,
                                  ednsflags=dns.edns.ECS, options=[ecs_option],
                                  want_dnssec=dnssec)


@pytest.mark.parametrize(
    ('host, record_type'),
    [('example.org', None)],
)
def test_dot_plain_query(make_message, record_type):
    """Send a query to the resolver over TLS and verify the response."""
    response = dns.query.tls(make_message, RESOLVER_IP)
    assert EXAMPLE_ORG_IP == get_rrset(response)


@pytest.mark.parametrize(
    ('host, record_type'),
    [('example.org', None)],
)
def test_doh_plain_query(make_message, record_type):
    """Send a query to the resolver over HTTPS and verify the response."""
    response = dns.query.https(make_message, RESOLVER_URL,
                               path='/dns-query', post=False)
    assert EXAMPLE_ORG_IP == get_rrset(response)


@pytest.mark.parametrize(
    ('host, ip, record_type, dnssec'),
    [('dyna.wikimedia.org', WESTCOAST_CANADA_IP, None, False)],
)
def test_dot_edns_query_ulsfo(make_message_edns,
                              host, ip, record_type, dnssec):
    """Send a query over TLS with the EDNS Client Subnet option.

    This test sends a query to Wikidough with the client subnet option. Since
    Wikidough has ECS enabled for queries to authoritative namservers operated
    by it, the response for a query is based on the source (client) subnet. In
    this case, if a query is sent from the west coast of Canada, the lookup
    should return the IP address for the Ulsfo cluster.
    """
    response = dns.query.tls(make_message_edns, RESOLVER_IP, record_type)
    assert ULSFO_IP == get_rrset(response)
    assert CODFW_IP != get_rrset(response)


@pytest.mark.parametrize(
    ('host, ip, record_type, dnssec'),
    [('dyna.wikimedia.org', EASTCOAST_CANADA_IP, None, False)],
)
def test_dot_edns_query_codfw(make_message_edns,
                              host, ip, record_type, dnssec):
    """Similar to test_dot_edns_query_ulsfo, but from a different subnet."""
    response = dns.query.tls(make_message_edns, RESOLVER_IP, record_type)
    assert CODFW_IP == get_rrset(response)
    assert ULSFO_IP != get_rrset(response)


@pytest.mark.parametrize(
    ('host, ip, record_type, dnssec'),
    [('o-o.myaddr.l.google.com', EASTCOAST_CANADA_IP, dns.rdatatype.TXT, False)],
)
def test_dot_edns_query_no_wikimedia(make_message_edns,
                                     host, ip, record_type, dnssec):
    """Tests if ECS is enabled for non-WMF nameservers.

    As described in make_message_edns(), ECS should _not_ be enabled for
    non-WMF authoritative nameservers to protect the privacy of clients and
    their IP addresses and a query to these servers should not send the ECS
    option. This test confirms that and is made possible by querying
    o-o.myaddr.l.google.com as it returns the address of the resolver and the
    client subnet, if any.

    To summarize, if only the address of the resolver (Wikidough) is returned
    in this test, ECS is not enabled in Wikidough (other than for WMF
    authoritative nameservers). But if the address of the client is returned in
    addition to that of the resolver, ECS is enabled.
    """
    response = dns.query.tls(make_message_edns, RESOLVER_IP, dns.rdatatype.TXT)
    resolver = get_rrset(response, record_type=dns.rdatatype.TXT).strip('"')

    # FIXME: This has changed since the anycasted IP, as expected; need to get
    # PRODUCTION_NETWORKS from network::constants?
    assert resolver in ("208.80.153.43", "208.80.153.6", "208.80.153.38")
    assert EASTCOAST_CANADA_IP != resolver


@pytest.mark.parametrize(
    ('host, ip, record_type, dnssec'),
    [('example.org', EASTCOAST_CANADA_IP, dns.rdatatype.A, True)],
)
def test_dnssec_do_bit(make_message_edns, host, ip, record_type, dnssec):
    """Checks for DNSSEC status support when the DO-bit is set.

    Wikidough has DNSSEC enabled through pdns-recursor, where we enable its
    highest level of DNSSEC support, `validate'. A more detailed description of
    what `validate' means can be found at
    https://docs.powerdns.com/recursor/dnssec.html#what-when but for our
    purpose, it means that Wikidough will always perform validation and return
    SERVFAIL for bogus/invalid responses regardless of the client's intention
    to validate. Additionally, Wikidough returns the AD-bit set in case the
    client sets +AD or +DO in the query.

    Enabling DNSSEC support in Wikidough was discussed in T259816.
    """
    response = dns.query.tls(make_message_edns, RESOLVER_IP, dns.rdatatype.A)
    flags = dns.flags.to_text(response.flags)
    assert "AD" in flags


@pytest.mark.parametrize(
    ('host, ip, record_type, dnssec'),
    [('example.org', EASTCOAST_CANADA_IP, dns.rdatatype.A, False)],
)
def test_dnssec_no_do_bit(make_message_edns, host, ip, record_type, dnssec):
    """Checks for DNSSEC status support when the DO-bit is not set.

    While similar to test_dnssec_set_status() above, this test ensures that the
    AD-bit is not set in the reply when the client does not set the DO-bit in
    the query.
    """
    response = dns.query.tls(make_message_edns, RESOLVER_IP, dns.rdatatype.A)
    flags = dns.flags.to_text(response.flags)
    assert "AD" not in flags

    # This is an additional test to verify that if the AD-bit is set but not
    # the DO-bit, the AD-bit will still be set in the reply. This matches
    # https://tools.ietf.org/html/rfc6840#section-5.7.
    make_message_edns.flags |= dns.flags.AD
    ad_response = dns.query.tls(make_message_edns, RESOLVER_IP, dns.rdatatype.A)
    ad_flags = dns.flags.to_text(ad_response.flags)
    assert "AD" in ad_flags


@pytest.mark.parametrize(
    ('host, record_type'),
    [('a.b.qnamemin-test.internet.nl', dns.rdatatype.TXT)],
)
def test_dot_qname_minimization(make_message, host, record_type):
    """Tests for QNAME minimisation support.

    Checks for Wikidough's QNAME minimisation support, enabled in the backend
    pdns-recursor. This test does not depend on the dnsdist frontend so
    checking it for DoT will cover DoH as well.
    """
    response = dns.query.tls(make_message, RESOLVER_IP, dns.rdatatype.TXT)
    qname_response = get_rrset(response, dns.rdatatype.TXT).strip('"')
    assert "HOORAY - QNAME minimisation is enabled on your resolver :)!" == \
           qname_response
    assert qname_response is not None


def test_doh_pages():
    """Tests supported paths for Wikidough's DNS over HTTPS frontend.

    Wikidough currently accepts queries on its DoH frontend at /dns-query and
    has a landing page at /. Anything else should return a 404.
    """
    landing_page = requests.get(RESOLVER_URL)
    assert landing_page.raise_for_status() is None
    assert 200 == landing_page.status_code

    # 400 is expected because we don't actually send the dns=query parameter;
    # that is done by test_doh_plain_query() above.
    query_page = requests.get(RESOLVER_URL + '/dns-query')
    assert 400 == query_page.status_code

    no_path_page = requests.get(RESOLVER_URL + '/random-path')
    assert 404 == no_path_page.status_code


def test_doh_response_headers():
    """Checks that the correct response headers are returned from a DoH query.

    This runs against a base list of response headers that we care about; we
    also try to avoid redundancy as dnsdist has similar tests.
    """
    message = dns.message.make_query("wikipedia.org", "A")
    url_params = base64.urlsafe_b64encode(message.to_wire())
    headers = {"content-type": "application/dns-message"}

    doh_response = requests.get(RESOLVER_URL + "/dns-query",
                                params={"dns": url_params}, headers=headers)
    doh_response.raise_for_status()

    response_headers = doh_response.headers

    # HSTS, set by customResponseHeaders.
    hsts_value = "max-age=106384710; includeSubDomains; preload"
    assert response_headers["strict-transport-security"] == hsts_value

    # cache-control, set by sendCacheControlHeaders.
    assert "cache-control" in response_headers.keys()
    assert "max-age" in response_headers["cache-control"]
