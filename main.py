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
            raise RuntimeError("BASAIIV: session already resolved")
        s.resolved = True
        s.resolution_hash = resolution_hash
        s.outcome = outcome

    def get_session(self, session_id: str) -> Optional[DiagnosticSession]:
        return self.state.sessions.get(session_id)

    def list_session_ids(self) -> List[str]:
        return list(self.state.sessions.keys())

    def set_category_cap(self, category: int, cap: int) -> None:
        if category < 1 or category > CATEGORY_COUNT:
            raise ValueError("BASAIIV: invalid category")
        self.state.category_caps[category] = max(0, cap)

    def set_paused(self, paused: bool) -> None:
        self.state.paused = paused

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.state.to_dict(), indent=2), encoding="utf-8")

    def load(self, path: str | Path) -> None:
        self.state = BASAIIVState.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


# -----------------------------------------------------------------------------
# Report builder
# -----------------------------------------------------------------------------


def build_report(session: DiagnosticSession, include_hints: bool = True) -> str:
    lines = [
        "# BASAIIV Report",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Session",
        f"Session ID: {session.session_id}",
        f"Reporter: {session.reporter_hex}",
        f"Category: {session.category} ({get_category_label(session.category)}) — {get_category_long_name(session.category)}",
        f"Opened: {datetime.fromtimestamp(session.opened_at_ts, tz=timezone.utc).isoformat()}",
        f"Resolved: {session.resolved}",
        f"Outcome: {session.outcome}",
        f"Step count: {session.step_count}",
        "",
    ]
    if include_hints:
        lines.append("## Suggested steps")
        for i, h in enumerate(get_hints(session.category), 1):
            lines.append(f"{i}. {h}")
        lines.append("")
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Stats
# -----------------------------------------------------------------------------


def stats_summary(manager: SessionManager) -> str:
    total = len(manager.state.sessions)
    resolved = sum(1 for s in manager.state.sessions.values() if s.resolved)
    lines = [
        f"Total sessions: {total}",
        f"Resolved: {resolved}",
        "By category:",
    ]
    for c in range(1, CATEGORY_COUNT + 1):
        count = manager.state.category_counts.get(c, 0)
        lines.append(f"  {get_category_label(c)}: {count}")
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Diagnostic flows (step-by-step scripts per category)
# -----------------------------------------------------------------------------

FLOWS: Dict[int, List[str]] = {
    1: [
        "Start: User reports connectivity issue.",
        "Step 1: Confirm scope (one device vs all, one site vs all).",
        "Step 2: Check physical link (cable/Wi‑Fi icon).",
        "Step 3: Run ping to gateway.",
        "Step 4: Run ping to 8.8.8.8.",
        "Step 5: If gateway fails, check router and NIC.",
        "Step 6: If 8.8.8.8 fails, check DNS or WAN.",
        "Step 7: Flush DNS cache.",
        "Step 8: Try different DNS server.",
        "Step 9: Disable VPN/proxy temporarily.",
        "Step 10: Check firewall rules.",
        "Step 11: Restart network stack (netsh winsock reset).",
        "Step 12: Escalate to ISP or network admin if WAN issue.",
    ],
    2: [
        "Start: User reports disk full or errors.",
        "Step 1: Check free space (all volumes).",
        "Step 2: Run Disk Cleanup or Storage Sense.",
        "Step 3: Identify largest folders (TreeSize/WinDirStat).",
        "Step 4: Remove temp, cache, or old installers.",
        "Step 5: Empty Recycle Bin and clear downloads.",
        "Step 6: Check cloud sync local cache size.",
        "Step 7: Run CHKDSK if errors reported.",
        "Step 8: Check SMART status if available.",
        "Step 9: Consider moving user data to another drive.",
        "Step 10: Disable hibernation to free space if needed.",
        "Step 11: Remove Windows.old if present after upgrade.",
        "Step 12: Escalate to backup/replace if hardware failure.",
    ],
    3: [
        "Start: User reports OS slowness, crash, or error.",
        "Step 1: Restart the computer.",
        "Step 2: Check Task Manager for high CPU/memory.",
        "Step 3: Review startup programs and disable unnecessary.",
        "Step 4: Install pending Windows/macOS updates.",
        "Step 5: Run sfc /scannow (Windows) or diskutil verifyVolume (macOS).",
        "Step 6: Check Event Viewer or Console for errors.",
        "Step 7: Boot Safe Mode to isolate driver/software.",
        "Step 8: Restore to previous restore point if available.",
        "Step 9: Run memory diagnostic.",
        "Step 10: Disable antivirus temporarily to test.",
        "Step 11: Create new user profile to test corruption.",
        "Step 12: Consider reset (keep files) or reinstall as last resort.",
    ],
    4: [
        "Start: User reports browser not loading or error.",
        "Step 1: Try incognito/private window.",
        "Step 2: Clear cache and cookies for the site.",
        "Step 3: Disable extensions one by one.",
        "Step 4: Update browser to latest version.",
        "Step 5: Check proxy and DNS in browser settings.",
        "Step 6: Try another browser to isolate.",
        "Step 7: Disable hardware acceleration.",
        "Step 8: Reset browser settings to default.",
        "Step 9: Check VPN or corporate proxy.",
        "Step 10: Verify certificate and date/time.",
        "Step 11: Test on another network.",
        "Step 12: Reinstall browser if profile corrupt.",
    ],
    5: [
        "Start: User reports device not working.",
        "Step 1: Check Device Manager for warnings.",
        "Step 2: Uninstall device and scan for hardware changes.",
        "Step 3: Install driver from Windows Update.",
        "Step 4: Install driver from manufacturer site.",
        "Step 5: Roll back driver if issue after update.",
        "Step 6: Try another USB/port or cable.",
        "Step 7: Update chipset/USB controller drivers.",
        "Step 8: Disable USB selective suspend.",
        "Step 9: Check firmware update for device.",
        "Step 10: Test on another computer.",
        "Step 11: Remove duplicate entries in Device Manager.",
        "Step 12: Escalate to hardware replacement if failed.",
    ],
    6: [
        "Start: User reports battery or power issue.",
        "Step 1: Check power plan and brightness.",
        "Step 2: Review Task Manager for background usage.",
        "Step 3: Run powercfg /batteryreport.",
        "Step 4: Calibrate battery (full cycle).",
        "Step 5: Update BIOS for power management.",
        "Step 6: Disable wake-on-LAN and USB wake.",
        "Step 7: Check charger and cable.",
        "Step 8: Verify adapter wattage meets spec.",
        "Step 9: Disable fast startup if sleep issues.",
        "Step 10: Check thermal throttling.",
        "Step 11: Replace battery if health very low.",
        "Step 12: Escalate to OEM if hardware fault.",
    ],
    7: [
        "Start: User reports display or graphics issue.",
        "Step 1: Check cable and connections.",
        "Step 2: Set correct resolution and refresh rate.",
        "Step 3: Update graphics driver from vendor.",
        "Step 4: Roll back driver if issue after update.",
        "Step 5: Try another monitor or TV.",
        "Step 6: Disable multi-monitor and re-enable.",
        "Step 7: Run display troubleshooter.",
        "Step 8: Disable hardware acceleration in app.",
        "Step 9: Check GPU temperature.",
        "Step 10: Try integrated graphics if available.",
        "Step 11: Verify monitor input source and OSD.",
        "Step 12: Escalate to GPU/monitor replacement.",
    ],
    8: [
        "Start: User reports no sound or audio issue.",
        "Step 1: Check physical volume and mute.",
        "Step 2: Set correct output device in Sound settings.",
        "Step 3: Run audio troubleshooter.",
        "Step 4: Update or reinstall audio driver.",
        "Step 5: Disable audio enhancements.",
        "Step 6: Check app-specific volume in mixer.",
        "Step 7: Unplug and replug USB/3.5mm device.",
        "Step 8: Set default format (e.g. 24-bit 48 kHz).",
        "Step 9: Disable exclusive mode.",
        "Step 10: Check communications device setting.",
        "Step 11: Test with another output device.",
        "Step 12: Escalate to hardware if device failed.",
    ],
}


def get_flow(category: int) -> List[str]:
    return list(FLOWS.get(category, []))


# -----------------------------------------------------------------------------
# Common issues and resolution snippets
# -----------------------------------------------------------------------------

COMMON_ISSUES: Dict[int, List[str]] = {
    1: ["No internet access", "Slow connection", "DNS resolution failed", "Limited connectivity", "Wi‑Fi drops frequently"],
    2: ["Disk full", "Slow disk access", "CHKDSK errors", "Drive not detected", "Permission denied"],
    3: ["PC slow", "Blue screen", "High CPU usage", "Updates failing", "Startup very slow"],
    4: ["Page not loading", "Slow browsing", "Certificate error", "Extension conflict", "Out of memory"],
    5: ["Device not recognized", "Yellow exclamation Device Manager", "Printer offline", "USB device failed"],
    6: ["Battery drains fast", "Will not charge", "Sleep not working", "Adapter not recognized"],
    7: ["No signal", "Wrong resolution", "Screen flicker", "Second monitor not detected"],
    8: ["No sound", "Wrong output device", "Crackling/popping", "Microphone not working"],
}

RESOLUTION_SNIPPETS: Dict[int, List[str]] = {
    1: ["Restarted router and modem; connectivity restored.", "Flushed DNS and changed to 1.1.1.1; resolution fixed."],
    2: ["Freed space with Disk Cleanup and Storage Sense; OK.", "Ran CHKDSK /f; bad sectors resolved."],
    3: ["Disabled startup apps; boot time improved.", "Installed pending updates; stability improved."],
    4: ["Cleared cache and cookies; site loads.", "Disabled extension; conflict resolved."],
    5: ["Reinstalled driver from manufacturer; device OK.", "Rolled back driver; stability restored."],
    6: ["Calibrated battery; percentage accurate.", "Updated BIOS; charge detection fixed."],
    7: ["Reseated cable; signal restored.", "Updated graphics driver; resolution list updated."],
    8: ["Set default playback device; sound working.", "Updated audio driver; crackling gone."],
}


def get_common_issues(category: int) -> List[str]:
    return list(COMMON_ISSUES.get(category, []))


def get_resolution_snippets(category: int) -> List[str]:
    return list(RESOLUTION_SNIPPETS.get(category, []))


# -----------------------------------------------------------------------------
# Extended hints (extra steps per category)
# -----------------------------------------------------------------------------

EXTENDED_HINTS: Dict[int, List[str]] = {
    1: [
        "Verify no IP conflict with another device.",
        "Check router admin page for blocked clients.",
        "Test with Ethernet if on Wi‑Fi to rule out wireless issues.",
        "Review recent router firmware updates.",
        "Confirm ISP outage status.",
        "Try tethering to phone to test if PC stack is fine.",
        "Inspect network adapter power management (allow off = no).",
        "Check for duplicate IPv4 addresses.",
        "Validate subnet mask and default gateway.",
        "Run netsh winsock reset (Windows).",
    ],
    2: [
        "Check Recycle Bin size and empty if needed.",
        "Use TreeSize or WinDirStat to find large folders.",
        "Verify SSD trim is enabled (Windows: fsutil behavior query DisableDeleteNotify).",
        "Check for Windows.old and remove via Disk Cleanup.",
        "Review cloud sync selective sync settings.",
        "Ensure no runaway download or temp folder.",
        "Check virtual memory / page file size.",
        "Consider moving user profile to another drive if system drive full.",
        "Verify external drive is not in read-only or failing.",
        "Run Storage Sense (Windows 10/11) to auto-clean.",
    ],
    3: [
        "Check Windows Update history for failed updates.",
        "Review reliability monitor (perfmon /rel).",
        "Temporarily disable antivirus to test.",
        "Check for corrupt user profile (new local user test).",
        "Verify system time and time zone.",
        "Run memory diagnostic (mdsched).",
        "Check for pending reboot (registry or wmic).",
        "Review application crash dumps in %LocalAppData%\\CrashDumps.",
        "Ensure no conflicting .NET versions.",
        "Check Windows activation status.",
    ],
    4: [
        "Test with a different user profile in the same browser.",
        "Check for browser updates in background.",
        "Verify no corporate proxy or SSL inspection breaking sites.",
        "Clear site data for the specific domain.",
        "Try disabling tracking protection for the site.",
        "Check if issue is only on one site or all sites.",
        "Review browser flags (chrome://flags) for experimental features.",
        "Ensure WebRTC or geolocation is not blocked if needed.",
        "Test with browser in no-sandbox mode for debugging.",
        "Check certificate errors (valid cert, correct date).",
    ],
    5: [
        "Check Windows Update optional updates for drivers.",
        "Use manufacturer-provided driver (not generic).",
        "Verify device appears in BIOS/UEFI.",
        "Try USB 2.0 port if device is USB 3 and flaky.",
        "Check for power delivery (USB-C) if applicable.",
        "Review Windows compatibility for the device.",
        "Uninstall all instances of the device and reboot.",
        "Check for firmware update for the peripheral.",
        "Verify no conflict with another driver (e.g. two mouse drivers).",
        "Test on another OS (e.g. Linux live USB) to isolate.",
    ],
    6: [
        "Check powercfg /devicequery wake_armed for wake sources.",
        "Review high power usage in Battery report.",
        "Disable unnecessary startup programs.",
        "Set GPU to power-saving when on battery.",
        "Check for BIOS power management settings.",
        "Verify charger wattage meets laptop requirement.",
        "Test with battery removed (AC only) if possible.",
        "Calibrate battery if percentage is wrong.",
        "Check for thermal throttling (high temp = lower performance).",
        "Review OEM power manager (Dell Command, Lenovo Vantage, etc.).",
    ],
    7: [
        "Check GPU temperature under load.",
        "Verify monitor supports the resolution/refresh requested.",
        "Try lowering resolution or refresh rate.",
        "Disable G-Sync/FreeSync to test for sync issues.",
        "Check for GPU driver timeout (TDR) in registry.",
        "Verify no loose connection at both ends.",
        "Try another video output on the GPU.",
        "Test with integrated graphics if available.",
        "Review HDR and color format settings.",
        "Check for firmware update for the monitor.",
    ],
    8: [
        "Set communications device to do nothing (Windows).",
        "Disable exclusive mode in Sound properties.",
        "Check for sample rate mismatch (e.g. 44.1 vs 48 kHz).",
        "Verify default device is correct in Sound settings.",
        "Test with built-in speakers vs external.",
        "Review spatial sound and enhancements.",
        "Check for duplicate playback devices.",
        "Ensure no app is holding exclusive access.",
        "Try WASAPI shared vs exclusive in supported apps.",
        "Verify no hardware mute or physical switch.",
    ],
}


def get_extended_hints(category: int) -> List[str]:
    return list(EXTENDED_HINTS.get(category, []))


# -----------------------------------------------------------------------------
# Check step names (for reporting)
# -----------------------------------------------------------------------------

def get_check_name(category: int, step_index: int) -> str:
    names: Dict[Tuple[int, int], str] = {
        (1, 0): "Verify physical link",
        (1, 1): "Ping gateway",
        (1, 2): "Ping external DNS",
        (1, 3): "Flush DNS cache",
        (1, 4): "Check adapter status",
        (1, 5): "Review firewall",
        (2, 0): "Check free space",
        (2, 1): "Run Disk Cleanup",
        (2, 2): "Identify large folders",
        (2, 3): "Clear temp and cache",
        (2, 4): "Empty Recycle Bin",
        (2, 5): "Run CHKDSK",
        (3, 0): "Restart computer",
        (3, 1): "Check Task Manager",
        (3, 2): "Review startup programs",
        (3, 3): "Install updates",
        (3, 4): "Run SFC/DISM",
        (3, 5): "Check Event Viewer",
        (4, 0): "Try incognito",
        (4, 1): "Clear cache/cookies",
        (4, 2): "Disable extensions",
        (4, 3): "Update browser",
        (4, 4): "Check proxy/DNS",
        (5, 0): "Check Device Manager",
        (5, 1): "Uninstall and rescan",
        (5, 2): "Windows Update driver",
        (5, 3): "Manufacturer driver",
        (6, 0): "Check power plan",
        (6, 1): "Review background apps",
        (6, 2): "Battery report",
        (6, 3): "Calibrate battery",
        (7, 0): "Check cable",
        (7, 1): "Set resolution/refresh",
        (7, 2): "Update graphics driver",
        (7, 3): "Roll back driver",
        (8, 0): "Check volume/mute",
        (8, 1): "Set output device",
        (8, 2): "Audio troubleshooter",
        (8, 3): "Update audio driver",
    }
    return names.get((category, step_index), f"Check step {step_index}")


# -----------------------------------------------------------------------------
# Export session to text
# -----------------------------------------------------------------------------

def export_session_to_text(session: DiagnosticSession) -> str:
    lines = [
        f"Session ID: {session.session_id}",
        f"Reporter: {session.reporter_hex}",
        f"Category: {session.category} ({get_category_label(session.category)})",
        f"Opened: {datetime.fromtimestamp(session.opened_at_ts, tz=timezone.utc).isoformat()}",
        f"Resolved: {session.resolved}",
        f"Outcome: {session.outcome}",
        f"Step count: {session.step_count}",
    ]
    for i, h in enumerate(session.steps):
        if h:
            lines.append(f"  Step {i}: {h}")
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Version and help
# -----------------------------------------------------------------------------

def get_version_string() -> str:
    return f"{APP_NAME} v{APP_VERSION} ({NAMESPACE})"


def get_full_help() -> str:
    return (
        "BASAIIV is a diagnostic support helper for day-to-day tech issues.\n"
        "Categories: 1=Network, 2=Disk, 3=OS, 4=Browser, 5=Driver, 6=Power, 7=Display, 8=Audio.\n"
        "Commands: open, hint, flow, list, get, report, stats, issues, resolutions, export, extended-hint, version, categories, help, health, recommend."
    )


# -----------------------------------------------------------------------------
# Outcome statistics
# -----------------------------------------------------------------------------

def outcome_stats(manager: SessionManager) -> str:
    resolved = sum(1 for s in manager.state.sessions.values() if s.resolved and s.outcome == OUTCOME_RESOLVED)
    escalated = sum(1 for s in manager.state.sessions.values() if s.resolved and s.outcome == OUTCOME_ESCALATED)
    deferred = sum(1 for s in manager.state.sessions.values() if s.resolved and s.outcome == OUTCOME_DEFERRED)
    return f"Resolved: {resolved}\nEscalated: {escalated}\nDeferred: {deferred}"


# -----------------------------------------------------------------------------
# Step templates (predefined step labels per category)
# -----------------------------------------------------------------------------

STEP_TEMPLATES: Dict[int, List[str]] = {
    1: [f"Network step {i+1}: Verify connectivity" if i % 3 == 0 else f"Network step {i+1}: Check configuration" if i % 3 == 1 else f"Network step {i+1}: Test path" for i in range(24)],
    2: [f"Disk step {i+1}: Check space or health" if i % 2 == 0 else f"Disk step {i+1}: Run tool or cleanup" for i in range(24)],
    3: [f"OS step {i+1}: Update" if i % 4 == 0 else f"OS step {i+1}: Restart" if i % 4 == 1 else f"OS step {i+1}: Scan" if i % 4 == 2 else f"OS step {i+1}: Reset" for i in range(28)],
    4: [f"Browser step {i+1}: Clear cache, extension, or setting" for i in range(20)],
    5: [f"Driver step {i+1}: Update, rollback, or reinstall device" for i in range(22)],
    6: [f"Power step {i+1}: Calibrate, plan, or hardware check" for i in range(18)],
    7: [f"Display step {i+1}: Cable, driver, or resolution" for i in range(20)],
    8: [f"Audio step {i+1}: Output device or driver" for i in range(18)],
}


def get_step_templates(category: int) -> List[str]:
    return list(STEP_TEMPLATES.get(category, []))


# -----------------------------------------------------------------------------
# Category long names (for reports)
# -----------------------------------------------------------------------------

def get_category_long_name(category: int) -> str:
    long_names = {
        1: "Network & connectivity (Wi‑Fi, Ethernet, DNS, VPN)",
        2: "Storage & disk (space, health, cleanup, external drives)",
        3: "Operating system (Windows, macOS, Linux – updates, slowness, crashes)",
        4: "Browser & web (Chrome, Edge, Firefox – loading, extensions, certificates)",
        5: "Drivers & peripherals (USB, printer, webcam, Device Manager)",
        6: "Power & battery (drain, charging, sleep, adapter)",
