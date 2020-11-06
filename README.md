# knead-wikidough ∡

## Integration tests for Wikidough

`knead-wikidough` is a test suite for production testing of [`Wikidough`](https://wikitech.wikimedia.org/wiki/Wikidough), a caching, recursive `DoH` (DNS-over-HTTPS) and `DoT` (DNS-over-TLS) resolver. Currently, it runs tests against `Wikidough` for the following categories:

* **TLS** (`test_tls.py`)
  * Checks for support of TLS protocols and their associated ciphers.

* **DNS** (`test_dns.py`)
  * Checks for DoH and DoT support, including `dnsdist` and `PowerDNS Recursor` configurations specific to `Wikidough`.

### Requirements

- Python 3.7+
- `tox`

`tox` fetches the additional Python libraries required, as specified in `tox.ini` and `requirements.txt`.

### Running the Tests

Running `tox` runs all tests under `tests/`.

If you want to run specific tests, `tox -e tls` will run the TLS tests while `tox -e dns` will run the DNS tests.
