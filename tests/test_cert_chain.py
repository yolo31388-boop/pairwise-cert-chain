import pytest

from security.cert_chain import (
    build_chain,
    name_constraints_ok,
    eku_ok,
    ocsp_ok,
    pin_ok
)


def test_build_chain():
    certs = {'leaf': {'issuer': 'mid'}, 'mid': {'issuer': 'root'}, 'root': {'issuer': 'root'}}
    assert build_chain('leaf', certs) == ['leaf', 'mid', 'root']

def test_cross_signed():
    certs = {'leaf': {'issuer': 'mid1'}, 'mid1': {'issuer': 'root1'}, 'root1': {'issuer': 'root1'}, 'mid2': {'issuer': 'root2'}, 'root2': {'issuer': 'root2'}}
    assert len(build_chain('leaf', certs)) == 3

def test_missing_issuer():
    assert build_chain('leaf', {'leaf': {'issuer': 'missing'}}) is None

def test_name_ok():
    assert name_constraints_ok([{'dns': ['*.example.com']}, {'dns': ['api.example.com']}], 'api.example.com') is True

def test_name_bad():
    assert name_constraints_ok([{'dns': ['*.example.com']}, {'dns': ['api.example.com']}], 'evil.com') is False

def test_eku_server():
    assert eku_ok({'eku': ['serverAuth']}, 'server') is True

def test_eku_client():
    assert eku_ok({'eku': ['clientAuth']}, 'server') is False

def test_ocsp_fresh():
    assert ocsp_ok({'thisUpdate': 90, 'nextUpdate': 110}, 100) is True

def test_ocsp_stale():
    assert ocsp_ok({'thisUpdate': 10, 'nextUpdate': 20}, 100) is False

def test_pin_match():
    assert pin_ok({'spki': 'abc'}, {'abc'}) is True

def test_pin_mismatch():
    assert pin_ok({'spki': 'abc'}, {'def'}) is False

def test_expired():
    assert ocsp_ok({'thisUpdate': 90, 'nextUpdate': 110, 'status': 'revoked'}, 100) is False

def test_untrusted_root():
    assert build_chain('leaf', {'leaf': {'issuer': 'root'}, 'root': {'issuer': 'root'}}, roots={'other'}) is None

def test_wildcard():
    assert name_constraints_ok([{'dns': ['*.example.com']}], 'a.b.example.com') is True

def test_empty_chain():
    assert build_chain('missing', {}) is None
