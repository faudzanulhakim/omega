"""Hermetic defaults for the omega test suite.

Autouse: the polyglot gate starts CLOSED for every test so no test can
accidentally execute real system binaries or native adapters just
because the host environment exports PTK_POLYGLOT=1. Tests that need
the gate open set PTK_POLYGLOT=1 explicitly (their fixtures run after
this autouse one and override it).
"""
import pytest


@pytest.fixture(autouse=True)
def _hermetic_polyglot_gate(monkeypatch):
    monkeypatch.delenv("PTK_POLYGLOT", raising=False)
