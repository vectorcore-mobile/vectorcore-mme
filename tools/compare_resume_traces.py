#!/usr/bin/env python3
"""Inventory and compare Cisco/VectorCore resume traces.

This tool is intentionally lightweight and shell-based so it can work against
existing lab captures without introducing new Python dependencies.

Supported inputs:
- pcap/pcapng captures (decoded via tshark/capinfos when available)
- Cisco/monitor ASCII traces similar to the files captured under /tmp

Usage:
  tools/compare_resume_traces.py inventory /tmp
  tools/compare_resume_traces.py compare <cisco-trace> <vectorcore-trace>
  tools/compare_resume_traces.py timeline <trace>
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Iterable


TEXT_EXTENSIONS = {".log", ".trace", ".txt"}
PCAP_EXTENSIONS = {".pcap", ".pcapng"}
ARCHIVE_EXTENSIONS = {".zip", ".tgz", ".tar.gz", ".gz"}

S1AP_PROCEDURE_NAMES = {
    "5": "ERABSetup",
    "6": "ERABModify",
    "7": "ERABRelease",
    "9": "InitialContextSetup",
    "11": "DownlinkNASTransport",
    "12": "InitialUEMessage",
    "13": "UplinkNASTransport",
    "17": "S1Setup",
    "18": "UEContextReleaseRequest",
    "22": "UECapabilityInfoIndication",
    "23": "UEContextRelease",
    "49": "PWSRestartIndication",
}

GTPV2_MESSAGE_NAMES = {
    "32": "CreateSessionRequest",
    "33": "CreateSessionResponse",
    "34": "ModifyBearerRequest",
    "35": "ModifyBearerResponse",
    "95": "CreateBearerRequest",
    "96": "CreateBearerResponse",
    "97": "UpdateBearerRequest",
    "98": "UpdateBearerResponse",
    "99": "DeleteBearerRequest",
    "100": "DeleteBearerResponse",
}


@dataclasses.dataclass
class TraceRecord:
    path: str
    file_type: str
    capture_timestamp: str = ""
    ue_identity: str = ""
    mme_implementation: str = ""
    procedure: str = ""
    interfaces: str = ""
    scenario: str = ""


@dataclasses.dataclass
class Event:
    rel_time: float | None
    category: str
    name: str
    detail: str = ""


def run(cmd: list[str], check: bool = True) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
    return proc.stdout


def file_type(path: pathlib.Path) -> str:
    try:
        return run(["file", str(path)]).strip()
    except Exception as exc:
        return f"file failed: {exc}"


def detect_mme_implementation(path: pathlib.Path, content: str = "") -> str:
    lower = f"{path.name}\n{content[:4000]}".lower()
    if "vectorcore" in lower:
        return "VectorCore"
    if "cisco" in lower or "qvpc" in lower:
        return "Cisco"
    if "nokia" in lower:
        return "Nokia"
    return ""


def detect_ue_identity(content: str) -> str:
    m = re.search(r"(?:IMSI|MSID/IMSI)\s*[:=]\s*([0-9]{12,15})", content)
    if m:
        return m.group(1)
    m = re.search(r"\b(311435[0-9]{9})\b", content)
    if m:
        return m.group(1)
    return ""


def classify_text_trace(path: pathlib.Path) -> TraceRecord:
    content = path.read_text(errors="ignore")
    mme = detect_mme_implementation(path, content)
    imsi = detect_ue_identity(content)
    procedure_parts: list[str] = []
    if "ATTACH_REQUEST(0x41)" in content:
        procedure_parts.append("initial_attach")
    if "SERVICE_REQUEST(0x4c)" in content or "NAS_MSG_SECURITY_HDR_SERVICE_REQUEST" in content:
        procedure_parts.append("service_request_resume")
    if "TRACKING_AREA_UPDATE_REQUEST(0x48)" in content:
        procedure_parts.append("tau_resume")
    if "INITIAL CONTEXT SETUP (9)" in content:
        procedure_parts.append("ics")
    if "User-inactivity (20)" in content:
        procedure_parts.append("release:user-inactivity")
    if "radio-connection-with-ue-lost" in content:
        procedure_parts.append("release:radio-loss")
    scenario = ""
    if "TRACKING_AREA_UPDATE_REQUEST(0x48)" in content:
        scenario = "active-flag TAU present"
    elif "NAS_MSG_SECURITY_HDR_SERVICE_REQUEST" in content:
        scenario = "service request present"
    elif "ATTACH_REQUEST(0x41)" in content:
        scenario = "initial attach present"
    return TraceRecord(
        path=str(path),
        file_type=file_type(path),
        capture_timestamp=extract_first_timestamp(content),
        ue_identity=imsi,
        mme_implementation=mme,
        procedure=",".join(procedure_parts),
        interfaces="S1AP/NAS text trace",
        scenario=scenario,
    )


def extract_first_timestamp(content: str) -> str:
    for line in content.splitlines():
        if re.search(r"\d{2}:\d{2}:\d{2}", line):
            return line.strip()
    return ""


def classify_pcap(path: pathlib.Path) -> TraceRecord:
    info = run(["capinfos", str(path)], check=False)
    summary = tshark_summary(path)
    return TraceRecord(
        path=str(path),
        file_type=file_type(path),
        capture_timestamp=extract_capinfos_value(info, "Earliest packet time"),
        ue_identity=summary.get("ue_identity", ""),
        mme_implementation=summary.get("mme_implementation", ""),
        procedure=",".join(summary.get("procedures", [])),
        interfaces=extract_capinfos_value(info, "Filter string"),
        scenario=summary.get("scenario", ""),
    )


def extract_capinfos_value(text: str, key: str) -> str:
    for line in text.splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    return ""


def tshark_summary(path: pathlib.Path) -> dict:
    procedures: set[str] = set()
    imsi = ""
    scenario = ""
    s1ap_out = run(
        [
            "tshark", "-r", str(path), "-Y", "s1ap.procedureCode",
            "-T", "fields", "-e", "s1ap.procedureCode",
        ],
        check=False,
    )
    for code in s1ap_out.splitlines():
        code = code.strip()
        if code in S1AP_PROCEDURE_NAMES:
            procedures.add(S1AP_PROCEDURE_NAMES[code])
    gtp_out = run(
        [
            "tshark", "-r", str(path), "-Y", "gtpv2.message_type",
            "-T", "fields", "-e", "gtpv2.message_type",
        ],
        check=False,
    )
    for code in gtp_out.splitlines():
        code = code.strip()
        if code in GTPV2_MESSAGE_NAMES:
            procedures.add(GTPV2_MESSAGE_NAMES[code])
    nas_out = run(
        [
            "tshark", "-r", str(path), "-Y", "nas_eps.emm.message_type || nas_eps.esm.message_type",
            "-T", "fields", "-e", "nas_eps.emm.message_type", "-e", "nas_eps.esm.message_type", "-e", "e212.imsi",
        ],
        check=False,
    )
    for line in nas_out.splitlines():
        emm_code, esm_code, observed_imsi = (line.split("\t") + ["", "", ""])[:3]
        observed_imsi = observed_imsi.strip()
        if observed_imsi and not imsi:
            imsi = observed_imsi
        emm_code = emm_code.strip()
        if emm_code == "72":
            scenario = "TAU present"
        elif emm_code == "65" and not scenario:
            scenario = "Attach present"
        elif emm_code == "76" and not scenario:
            scenario = "Service Request present"
    mme = "VectorCore" if "MME-emm-debug" in path.name else ""
    return {
        "ue_identity": imsi,
        "mme_implementation": mme,
        "procedures": sorted(procedures),
        "scenario": scenario,
    }


def walk_with_max_depth(root: pathlib.Path, max_depth: int) -> Iterable[pathlib.Path]:
    root = root.resolve()
    for current_root, dirnames, filenames in os.walk(root):
        current_path = pathlib.Path(current_root)
        depth = len(current_path.relative_to(root).parts)
        if depth >= max_depth:
            dirnames[:] = []
        for filename in filenames:
            yield current_path / filename


def inventory(root: pathlib.Path, max_depth: int = 3) -> list[TraceRecord]:
    records: list[TraceRecord] = []
    for path in sorted(walk_with_max_depth(root, max_depth)):
        name = path.name.lower()
        if not (
            any(token in name for token in ("cisco", "mme", "sonim", "nokia"))
            or any(name.endswith(ext) for ext in TEXT_EXTENSIONS | PCAP_EXTENSIONS | ARCHIVE_EXTENSIONS)
        ):
            continue
        if any(name.endswith(ext) for ext in PCAP_EXTENSIONS):
            records.append(classify_pcap(path))
        elif any(name.endswith(ext) for ext in TEXT_EXTENSIONS):
            records.append(classify_text_trace(path))
        elif any(name.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
            records.append(
                TraceRecord(
                    path=str(path),
                    file_type=file_type(path),
                    mme_implementation=detect_mme_implementation(path),
                )
            )
    return records


def text_timeline(path: pathlib.Path) -> list[Event]:
    lines = path.read_text(errors="ignore").splitlines()
    events: list[Event] = []
    current_time: float | None = None
    for i, line in enumerate(lines):
        ts = re.search(r"(\d{2}):(\d{2}):(\d{2})[:.](\d{3})", line)
        if ts:
            hh, mm, ss, ms = map(int, ts.groups())
            current_time = hh * 3600 + mm * 60 + ss + ms / 1000.0
        if "Procedure Code :" in line:
            name = line.split(":", 1)[1].strip()
            events.append(Event(current_time, "s1ap", name))
        if "Message Type" in line and i + 1 < len(lines):
            name = lines[i + 1].strip()
            if name:
                events.append(Event(current_time, "nas", name))
        if "SecurityKey Value" in line and i + 2 < len(lines):
            key_line = lines[i + 2].strip()
            events.append(Event(current_time, "security", "SecurityKey", key_line))
        if "User-inactivity (20)" in line:
            events.append(Event(current_time, "release", "user-inactivity"))
        if "radio-connection-with-ue-lost" in line:
            events.append(Event(current_time, "release", "radio-connection-with-ue-lost"))
    return normalize_timeline(events)


def pcap_timeline(path: pathlib.Path) -> list[Event]:
    events: list[Event] = []
    s1ap_out = run(
        [
            "tshark", "-r", str(path), "-Y", "s1ap.procedureCode",
            "-T", "fields", "-e", "frame.time_epoch", "-e", "s1ap.procedureCode", "-e", "s1ap.CauseRadioNetwork",
        ],
        check=False,
    )
    for line in s1ap_out.splitlines():
        epoch, code, release_cause = (line.split("\t") + ["", "", ""])[:3]
        rel = float(epoch) if epoch else None
        code = code.strip()
        release_cause = release_cause.strip()
        if code:
            events.append(Event(rel, "s1ap", S1AP_PROCEDURE_NAMES.get(code, code)))
        if release_cause:
            events.append(Event(rel, "release", release_cause))
    gtp_out = run(
        [
            "tshark", "-r", str(path), "-Y", "gtpv2.message_type",
            "-T", "fields", "-e", "frame.time_epoch", "-e", "gtpv2.message_type",
        ],
        check=False,
    )
    for line in gtp_out.splitlines():
        epoch, code = (line.split("\t") + ["", ""])[:2]
        rel = float(epoch) if epoch else None
        code = code.strip()
        if code:
            events.append(Event(rel, "s11", GTPV2_MESSAGE_NAMES.get(code, code)))
    nas_out = run(
        [
            "tshark", "-r", str(path), "-Y", "nas_eps.emm.message_type || nas_eps.esm.message_type",
            "-T", "fields", "-e", "frame.time_epoch", "-e", "nas_eps.emm.message_type", "-e", "nas_eps.esm.message_type",
        ],
        check=False,
    )
    for line in nas_out.splitlines():
        epoch, emm_code, esm_code = (line.split("\t") + ["", "", ""])[:3]
        rel = float(epoch) if epoch else None
        emm_code = emm_code.strip()
        esm_code = esm_code.strip()
        if emm_code:
            events.append(Event(rel, "emm", f"EMM-{emm_code}"))
        if esm_code:
            events.append(Event(rel, "esm", f"ESM-{esm_code}"))
    return normalize_timeline(events)


def normalize_timeline(events: list[Event]) -> list[Event]:
    base = next((e.rel_time for e in events if e.rel_time is not None), None)
    if base is None:
        return events
    out = []
    for event in events:
        rel = None if event.rel_time is None else event.rel_time - base
        out.append(Event(rel, event.category, event.name, event.detail))
    return out


def load_timeline(path: pathlib.Path) -> list[Event]:
    lower = path.name.lower()
    if any(lower.endswith(ext) for ext in PCAP_EXTENSIONS):
        return pcap_timeline(path)
    return text_timeline(path)


def render_timeline(events: Iterable[Event]) -> str:
    lines = []
    for event in events:
        rel = "n/a" if event.rel_time is None else f"{event.rel_time:8.3f}s"
        detail = f" | {event.detail}" if event.detail else ""
        lines.append(f"{rel} | {event.category:8s} | {event.name}{detail}")
    return "\n".join(lines)


def compare(left: pathlib.Path, right: pathlib.Path) -> dict:
    left_events = load_timeline(left)
    right_events = load_timeline(right)
    return {
        "left": str(left),
        "right": str(right),
        "left_timeline": [dataclasses.asdict(e) for e in left_events],
        "right_timeline": [dataclasses.asdict(e) for e in right_events],
        "left_event_names": [e.name for e in left_events],
        "right_event_names": [e.name for e in right_events],
        "left_only_events": sorted(set(e.name for e in left_events) - set(e.name for e in right_events)),
        "right_only_events": sorted(set(e.name for e in right_events) - set(e.name for e in left_events)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_inventory = sub.add_parser("inventory")
    p_inventory.add_argument("root")
    p_inventory.add_argument("--max-depth", type=int, default=3)

    p_timeline = sub.add_parser("timeline")
    p_timeline.add_argument("trace")

    p_compare = sub.add_parser("compare")
    p_compare.add_argument("left")
    p_compare.add_argument("right")
    p_compare.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.cmd == "inventory":
        records = [dataclasses.asdict(r) for r in inventory(pathlib.Path(args.root), args.max_depth)]
        print(json.dumps(records, indent=2))
        return 0

    if args.cmd == "timeline":
        print(render_timeline(load_timeline(pathlib.Path(args.trace))))
        return 0

    if args.cmd == "compare":
        result = compare(pathlib.Path(args.left), pathlib.Path(args.right))
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Left:  {result['left']}")
            print(f"Right: {result['right']}")
            print("\nLeft timeline:")
            print(render_timeline(load_timeline(pathlib.Path(args.left))))
            print("\nRight timeline:")
            print(render_timeline(load_timeline(pathlib.Path(args.right))))
            print("\nLeft-only events:")
            print("\n".join(result["left_only_events"]) or "(none)")
            print("\nRight-only events:")
            print("\n".join(result["right_only_events"]) or "(none)")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
