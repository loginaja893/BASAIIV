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
            "sessions": {
                k: {
                    "session_id": v.session_id,
                    "reporter_hex": v.reporter_hex,
                    "category": v.category,
                    "opened_at_ts": v.opened_at_ts,
                    "resolved": v.resolved,
                    "resolution_hash": v.resolution_hash,
                    "outcome": v.outcome,
                    "step_count": v.step_count,
                    "steps": v.steps,
                }
                for k, v in self.sessions.items()
            },
            "category_counts": self.category_counts,
            "category_caps": self.category_caps,
            "session_counter": self.session_counter,
            "paused": self.paused,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> BASAIIVState:
        state = cls()
        state.session_counter = d.get("session_counter", 0)
        state.paused = d.get("paused", False)
        state.category_counts = d.get("category_counts", {i: 0 for i in range(1, CATEGORY_COUNT + 1)})
        state.category_caps = d.get("category_caps", {i: MAX_SESSIONS_PER_CATEGORY for i in range(1, CATEGORY_COUNT + 1)})
        for k, v in d.get("sessions", {}).items():
            state.sessions[k] = DiagnosticSession(
                session_id=v["session_id"],
                reporter_hex=v["reporter_hex"],
                category=v["category"],
                opened_at_ts=v["opened_at_ts"],
                resolved=v["resolved"],
                resolution_hash=v["resolution_hash"],
                outcome=v["outcome"],
                step_count=v["step_count"],
                steps=v.get("steps", []),
            )
        return state


# -----------------------------------------------------------------------------
# Category labels
# -----------------------------------------------------------------------------

CATEGORY_LABELS = {
    1: "Network & connectivity",
    2: "Storage & disk",
    3: "Operating system",
    4: "Browser & web",
    5: "Drivers & peripherals",
    6: "Power & battery",
    7: "Display & graphics",
    8: "Audio & sound",
}


def get_category_label(category: int) -> str:
    return CATEGORY_LABELS.get(category, "Unknown")


# -----------------------------------------------------------------------------
# Hints per category (AI-helper suggested steps)
# -----------------------------------------------------------------------------

HINTS: Dict[int, List[str]] = {
    1: [
        "Check physical cable/Wi‑Fi connection.",
        "Run network troubleshooter (Windows: Settings > Network).",
        "Flush DNS: ipconfig /flushdns (Windows) or sudo dscacheutil -flushcache (macOS).",
        "Restart router and modem.",
        "Verify IP configuration (DHCP vs static).",
        "Disable and re-enable the network adapter.",
        "Check firewall/antivirus for blocked traffic.",
        "Ping gateway and 8.8.8.8 to isolate path.",
        "Try another DNS (e.g. 1.1.1.1 or 8.8.4.4).",
        "Review proxy/VPN settings.",
        "Check for driver updates for the NIC.",
        "Confirm no MAC filtering or captive portal.",
    ],
    2: [
        "Check free space (disk cleanup / Storage Sense).",
        "Run CHKDSK (Windows) or fsck (Linux/macOS).",
        "Verify drive health (SMART status).",
        "Defragment if HDD (not needed for SSD).",
        "Check for large temp/cache folders.",
        "Ensure drive is properly connected (SATA/USB).",
        "Review OneDrive/Dropbox sync and local cache.",
        "Check disk permissions.",
        "Disable hibernation to free space (powercfg -h off).",
        "Move user folders to another volume if needed.",
        "Check for runaway logs or dump files.",
        "Consider replacing drive if SMART errors.",
    ],
    3: [
        "Restart the computer.",
        "Install pending Windows/macOS/Linux updates.",
        "Boot into Safe Mode to isolate driver/software.",
        "Check Task Manager for high CPU/memory usage.",
        "Run sfc /scannow (Windows) or diskutil verifyVolume (macOS).",
        "Review startup programs and disable unnecessary ones.",
        "Check Event Viewer / Console for errors.",
        "Restore to a previous restore point if available.",
        "Reset Windows (Keep my files) or reinstall as last resort.",
        "Verify system file integrity (DISM on Windows).",
        "Check for conflicting security software.",
        "Ensure BIOS/UEFI and drivers are up to date.",
    ],
    4: [
        "Clear cache and cookies.",
        "Disable extensions one by one to find conflict.",
        "Try incognito/private window.",
        "Update browser to latest version.",
        "Reset browser settings to default.",
        "Check proxy and DNS settings in browser.",
        "Disable hardware acceleration.",
        "Try another browser to isolate issue.",
        "Remove and re-add profile.",
        "Check for conflicting VPN or firewall.",
        "Ensure JavaScript and cookies are allowed for the site.",
        "Review site permissions (camera, mic, location).",
    ],
    5: [
        "Update device driver from manufacturer or Windows Update.",
        "Uninstall device and scan for hardware changes.",
        "Roll back driver if issue started after update.",
        "Check Device Manager for yellow exclamation marks.",
        "Ensure USB/Thunderbolt controller drivers are current.",
        "Try another port or cable.",
        "Install manufacturer-specific utility (e.g. Logitech, Dell).",
        "Check for firmware update for the device.",
        "Disable USB selective suspend in power options.",
        "Verify device works on another machine.",
        "Remove duplicate or ghost devices in Device Manager.",
        "Check Group Policy for driver installation restrictions.",
    ],
    6: [
        "Calibrate battery (full discharge then full charge).",
        "Check power plan (Balanced/High performance).",
        "Reduce screen brightness and close heavy apps.",
        "Disable unused USB devices and wake-on-LAN if not needed.",
        "Review Task Manager for background apps using CPU.",
        "Replace battery if health is low (manufacturer tool).",
        "Check power adapter and cable; try another if possible.",
        "Update BIOS for power management fixes.",
        "Disable fast startup (can cause wake/sleep issues).",
        "Check outlet and surge protector.",
        "Verify hibernation and sleep settings.",
        "Run power report: powercfg /batteryreport (Windows).",
    ],
    7: [
        "Check cable connections (HDMI/DisplayPort).",
        "Update graphics driver from GPU vendor (NVIDIA/AMD/Intel).",
        "Set correct resolution and refresh rate in display settings.",
        "Try another monitor or TV to isolate.",
        "Disable multiple display and re-enable.",
        "Roll back graphics driver if issue after update.",
        "Check for overheating (clean fans, repaste).",
        "Run display troubleshooter (Windows).",
        "Disable hardware acceleration in apps if artifacts.",
        "Verify monitor OSD settings (input source).",
        "Try different cable (e.g. HDMI 2.0 for 4K).",
        "Reset monitor to factory defaults.",
    ],
    8: [
        "Check physical volume and mute buttons.",
        "Set correct output device (speakers/headphones).",
        "Run audio troubleshooter (Windows).",
        "Update or reinstall audio driver.",
        "Disable audio enhancements (Windows Sound properties).",
        "Verify default format (e.g. 24-bit 48000 Hz).",
        "Check app-specific volume (mixer).",
        "Unplug and replug USB/3.5mm device.",
        "Reset sound settings to default.",
        "Check for conflicting audio software.",
        "Verify HDMI/DisplayPort audio if using monitor speakers.",
        "Test with another device to isolate hardware.",
    ],
}


def get_hints(category: int) -> List[str]:
    return list(HINTS.get(category, []))


def get_first_hint(category: int) -> str:
    hints = HINTS.get(category, [])
    return hints[0] if hints else "No hints for this category."


# -----------------------------------------------------------------------------
# Hash and session ID
# -----------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def session_id_from(reporter_hex: str, category: int, nonce: int) -> str:
    payload = f"{NAMESPACE}:{reporter_hex}:{category}:{nonce}"
    return sha256_hex(payload.encode("utf-8"))


def step_hash_from(session_id: str, step_index: int, description: str) -> str:
    payload = f"{session_id}:{step_index}:{description or ''}"
    return sha256_hex(payload.encode("utf-8"))


def resolution_hash_from(session_id: str, summary: str) -> str:
    payload = f"{session_id}:{summary or ''}"
    return sha256_hex(payload.encode("utf-8"))


# -----------------------------------------------------------------------------
# Session manager
# -----------------------------------------------------------------------------


class SessionManager:
    def __init__(self, state: Optional[BASAIIVState] = None):
        self.state = state or BASAIIVState()

    def open_session(self, reporter_hex: str, category: int) -> str:
        if self.state.paused:
            raise RuntimeError("BASAIIV: registry paused")
        if category < 1 or category > CATEGORY_COUNT:
            raise ValueError("BASAIIV: invalid category")
        if self.state.category_counts.get(category, 0) >= self.state.category_caps.get(category, MAX_SESSIONS_PER_CATEGORY):
            raise RuntimeError("BASAIIV: category cap reached")
        reporter_hex = reporter_hex or ZERO_HEX
        self.state.session_counter += 1
        sid = session_id_from(reporter_hex, category, self.state.session_counter)
        if sid in self.state.sessions:
            raise RuntimeError("BASAIIV: session id collision")
        self.state.sessions[sid] = DiagnosticSession(
            session_id=sid,
            reporter_hex=reporter_hex,
            category=category,
            opened_at_ts=datetime.now(timezone.utc).timestamp(),
            resolved=False,
            resolution_hash="",
            outcome=OUTCOME_NONE,
            step_count=0,
            steps=[],
        )
        self.state.category_counts[category] = self.state.category_counts.get(category, 0) + 1
        return sid

    def record_step(self, session_id: str, step_index: int, step_hash: str) -> None:
        if session_id not in self.state.sessions:
            raise KeyError("BASAIIV: session not found")
        s = self.state.sessions[session_id]
        if s.resolved:
            raise RuntimeError("BASAIIV: session already resolved")
        if step_index < 0 or step_index >= MAX_STEPS_PER_SESSION:
            raise ValueError("BASAIIV: step index out of range")
        while len(s.steps) <= step_index:
            s.steps.append("")
        s.steps[step_index] = step_hash
        s.step_count = max(s.step_count, step_index + 1)

    def attest_resolution(self, session_id: str, resolution_hash: str, outcome: int, triage_keeper: str) -> None:
        if session_id not in self.state.sessions:
            raise KeyError("BASAIIV: session not found")
        if outcome < 0 or outcome >= OUTCOME_CAP:
            raise ValueError("BASAIIV: outcome out of range")
        if triage_keeper != TRIAGE_KEEPER_HEX:
            raise RuntimeError("BASAIIV: triage keeper only")
        s = self.state.sessions[session_id]
        if s.resolved:
