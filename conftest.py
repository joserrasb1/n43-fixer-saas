# -*- coding: utf-8 -*-
"""
conftest.py
-----------
Fixtures comunes para pytest
"""

from __future__ import annotations

import pytest

from parser_engine import N43Parser


@pytest.fixture
def parser() -> N43Parser:
    return N43Parser("test.txt")
