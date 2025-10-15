# tests/test_cache.py
import os
import sqlite3
import json
import tempfile
from vulnscan.vulnscan import cache

def test_cache_set_and_get(tmp_path, monkeypatch):
    # use a temporary DB file via env override
    dbfile = tmp_path / "test_cache.db"
    monkeypatch.setenv("VULNSCAN_CACHE_DB", str(dbfile))

    # ensure db is empty and functions work
    cache.init_db()
    assert dbfile.exists()

    key = "test:key:1"
    payload = {"a": 1, "b": "x"}
    cache.set_cached(key, payload)

    loaded = cache.get_cached(key)
    assert isinstance(loaded, dict)
    assert loaded["a"] == 1 and loaded["b"] == "x"

def test_get_cached_missing(tmp_path, monkeypatch):
    dbfile = tmp_path / "does_not_exist.db"
    monkeypatch.setenv("VULNSCAN_CACHE_DB", str(dbfile))
    # no init_db call: get_cached should safely return None
    assert cache.get_cached("nope") is None
