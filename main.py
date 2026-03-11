#!/usr/bin/env python3
"""
BASAIIV — Support and diagnostic helper for day-to-day tech issues.
AI-helper style: categories, steps, sessions, reports. Single-file app.
Pairs with BetterDiagnosticsDIGI contract and Java tool.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

APP_NAME = "BASAIIV"
APP_VERSION = "2.0.0"
DEFAULT_STATE_FILE = "basaiiv_state.json"
NAMESPACE = "BASAIIV.v1"
MAX_STEPS_PER_SESSION = 87
MAX_SESSIONS_PER_CATEGORY = 4127
CATEGORY_COUNT = 8
MAX_BATCH_OPEN = 19
OUTCOME_NONE, OUTCOME_RESOLVED, OUTCOME_ESCALATED, OUTCOME_DEFERRED = 0, 1, 2, 3
OUTCOME_CAP = 4
SESSION_ID_BYTES = 32
TRIAGE_KEEPER_HEX = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
ZERO_HEX = "0x0000000000000000000000000000000000000000"
SESSION_TIMEOUT_SEC = 86400

# -----------------------------------------------------------------------------
# Data models
# -----------------------------------------------------------------------------


@dataclass
class DiagnosticSession:
    session_id: str
    reporter_hex: str
    category: int
    opened_at_ts: float
    resolved: bool
    resolution_hash: str
    outcome: int
    step_count: int
    steps: List[str] = field(default_factory=list)


@dataclass
class BASAIIVState:
    sessions: Dict[str, DiagnosticSession] = field(default_factory=dict)
    category_counts: Dict[int, int] = field(default_factory=lambda: {i: 0 for i in range(1, CATEGORY_COUNT + 1)})
    category_caps: Dict[int, int] = field(default_factory=lambda: {i: MAX_SESSIONS_PER_CATEGORY for i in range(1, CATEGORY_COUNT + 1)})
    session_counter: int = 0
    paused: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
