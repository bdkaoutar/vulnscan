
import os
import json
import pytest
from vulnscan.vulnscan import cve_lookup, cache

def test_query_osv_package_caches_response(tmp_path, monkeypatch, requests_mock):
    # configure temporary DB
    dbfile = tmp_path / "cve_cache.db"
    monkeypatch.setenv("VULNSCAN_CACHE_DB", str(dbfile))
    cache.init_db()

    # prepare fake response
    fake_resp = {"vulns": [{"id": "CVE-FAKE-1", "summary": "fake vuln"}]}
    # mock the OSV endpoint
    requests_mock.post(cve_lookup.OSV_API, json=fake_resp, status_code=200)

    # first call: hits mocked API and caches
    result1 = cve_lookup.query_osv_package("pypi", "example-pkg", "1.2.3")
    assert result1 == fake_resp

    # second call: should read from cache (no additional HTTP requests)
    # to ensure no network call, re-mock to raise if called
    requests_mock.post(cve_lookup.OSV_API, exc=RuntimeError("should not be called"))
    result2 = cve_lookup.query_osv_package("pypi", "example-pkg", "1.2.3")
    assert result2 == fake_resp

def test_query_osv_package_http_error(tmp_path, monkeypatch, requests_mock):
    dbfile = tmp_path / "cve_cache2.db"
    monkeypatch.setenv("VULNSCAN_CACHE_DB", str(dbfile))
    cache.init_db()

    # simulate OSV returning 500
    requests_mock.post(cve_lookup.OSV_API, status_code=500, json={"error": "oops"})
    with pytest.raises(Exception):
        cve_lookup.query_osv_package("pypi", "example-pkg", "0.0.1")
