#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 pangea.org Associació Pangea - Coordinadora Comunicació per a la Cooperació
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
workbench-openwrt.py - Hardware snapshot tool for OpenWrt routers.

Connects to an OpenWrt device via SSH and collects hardware information,
producing a JSON snapshot compatible with DeviceHub.

Requirements:
    - Python 3.6+ (stdlib only, no pip dependencies)
    - SSH access to the target OpenWrt device
    - The target must be running OpenWrt (uses ubus, iwinfo, uci)
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone

VERSION = "0.0.1"
SOFTWARE = "workbench-script-openwrt"

logger = logging.getLogger("workbench-openwrt")


# --- SSH command execution ---

class OpenWrtSSH:
    """Run commands on an OpenWrt device over SSH."""

    def __init__(self, host, port=22, user="root", identity_file=None):
        self.host = host
        self.port = port
        self.user = user
        self.identity_file = identity_file

    def _ssh_base(self):
        cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-p", str(self.port),
        ]
        if self.identity_file:
            cmd += ["-i", self.identity_file]
        cmd.append(f"{self.user}@{self.host}")
        return cmd

    def run(self, command):
        """Execute a command on the remote device and return stdout."""
        full_cmd = self._ssh_base() + [command]
        logger.debug("ssh: %s", command)
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0 and result.stderr.strip():
                logger.debug("ssh stderr: %s", result.stderr.strip())
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning("Command timed out: %s", command)
            return ""
        except FileNotFoundError:
            logger.error("ssh binary not found. Is OpenSSH installed?")
            sys.exit(1)

    def run_json(self, command):
        """Execute a command and parse stdout as JSON."""
        output = self.run(command)
        if not output.strip():
            return {}
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON from: %s", command)
            return {}

    def read_file(self, path):
        """Read a file from the remote device."""
        return self.run(f"cat {path} 2>/dev/null")

    def test_connection(self):
        """Verify SSH connectivity."""
        output = self.run("echo ok")
        if output.strip() != "ok":
            logger.error("Cannot connect to %s@%s:%s", self.user, self.host, self.port)
            sys.exit(1)
        logger.info("Connected to %s@%s", self.user, self.host)


# --- Data collectors ---

def collect_board(ssh):
    """System board info via ubus (model, kernel, release, etc.)."""
    return ssh.run_json("ubus call system board")


def collect_system_info(ssh):
    """System runtime info (uptime, memory, load)."""
    return ssh.run_json("ubus call system info")


def collect_cpu(ssh):
    """CPU information from /proc/cpuinfo."""
    raw = ssh.read_file("/proc/cpuinfo")
    if not raw:
        return {}

    lines = raw.strip().splitlines()
    num_cores = sum(1 for l in lines if l.startswith("processor"))

    def first_match(key):
        for l in lines:
            if l.lower().startswith(key.lower()):
                return l.split(":", 1)[1].strip()
        return ""

    # ARM: "CPU part", x86: "model name"
    model = first_match("model name") or first_match("Hardware") or first_match("CPU part")
    arch = first_match("CPU architecture")
    features = first_match("Features") or first_match("flags")
    bogomips = first_match("BogoMIPS")

    # CPU frequency if available
    freq_raw = ssh.read_file("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").strip()
    max_freq_khz = int(freq_raw) if freq_raw.isdigit() else None

    return {
        "num_cores": num_cores,
        "model": model,
        "architecture": arch,
        "features": features,
        "bogomips": bogomips,
        "max_freq_khz": max_freq_khz,
    }


def collect_memory(ssh):
    """Memory info from /proc/meminfo."""
    raw = ssh.read_file("/proc/meminfo")
    if not raw:
        return {}

    def get_kb(key):
        m = re.search(rf"^{key}:\s+(\d+)", raw, re.MULTILINE)
        return int(m.group(1)) if m else 0

    return {
        "total_kb": get_kb("MemTotal"),
        "free_kb": get_kb("MemFree"),
        "available_kb": get_kb("MemAvailable"),
    }


def collect_storage(ssh):
    """Flash / storage: MTD partitions, UBI volumes, filesystem usage."""
    # MTD partitions
    mtd_partitions = []
    mtd_raw = ssh.read_file("/proc/mtd")
    for line in mtd_raw.strip().splitlines():
        if line.startswith("dev:") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            size_hex = parts[1]
            mtd_partitions.append({
                "device": parts[0].rstrip(":"),
                "name": parts[3].strip('"'),
                "size_bytes": int(size_hex, 16),
                "erasesize": "0x" + parts[2],
            })

    # UBI volumes - batch read
    ubi_volumes = []
    ubi_raw = ssh.run(
        'for d in /sys/class/ubi/ubi0_*; do '
        '[ -d "$d" ] || continue; '
        'echo "$(basename $d)|$(cat $d/name 2>/dev/null)|$(cat $d/data_bytes 2>/dev/null)|$(cat $d/type 2>/dev/null)"; '
        'done'
    )
    for line in ubi_raw.strip().splitlines():
        parts = line.split("|")
        if len(parts) >= 4:
            ubi_volumes.append({
                "id": parts[0],
                "name": parts[1],
                "size_bytes": int(parts[2]) if parts[2].isdigit() else 0,
                "type": parts[3],
            })

    # Filesystem usage
    filesystems = []
    df_raw = ssh.run("df -k 2>/dev/null")
    for line in df_raw.strip().splitlines():
        if line.startswith("Filesystem"):
            continue
        parts = line.split()
        if len(parts) >= 6:
            filesystems.append({
                "filesystem": parts[0],
                "size_kb": int(parts[1]) if parts[1].isdigit() else 0,
                "used_kb": int(parts[2]) if parts[2].isdigit() else 0,
                "available_kb": int(parts[3]) if parts[3].isdigit() else 0,
                "use_percent": parts[4],
                "mount": parts[5],
            })

    return {
        "mtd": mtd_partitions,
        "ubi": ubi_volumes,
        "filesystems": filesystems,
    }


def collect_network(ssh):
    """Network interfaces from /sys/class/net/."""
    # Batch: read all interface attributes in a single SSH call
    script = (
        'for iface in /sys/class/net/*; do '
        'name=$(basename "$iface"); '
        '[ "$name" = "lo" ] && continue; '
        'mac=$(cat "$iface/address" 2>/dev/null); '
        'state=$(cat "$iface/operstate" 2>/dev/null); '
        'mtu=$(cat "$iface/mtu" 2>/dev/null); '
        'speed=$(cat "$iface/speed" 2>/dev/null); '
        'echo "$name|$mac|$state|$mtu|$speed"; '
        'done'
    )
    raw = ssh.run(script)
    interfaces = []
    for line in raw.strip().splitlines():
        parts = line.split("|")
        if len(parts) < 4:
            continue
        name, mac, state, mtu = parts[0], parts[1], parts[2], parts[3]
        speed = parts[4] if len(parts) > 4 else ""

        entry = {
            "name": name,
            "mac": mac,
            "state": state,
            "mtu": int(mtu) if mtu.isdigit() else 0,
        }
        if speed.isdigit() and int(speed) > 0:
            entry["speed_mbps"] = int(speed)

        interfaces.append(entry)

    return {"interfaces": interfaces}


def collect_wifi(ssh):
    """WiFi radio info via uci, iwinfo, and ubus."""
    # Radio devices from uci - batch all reads
    radios = []
    uci_raw = ssh.run("uci show wireless 2>/dev/null")
    devices = []
    for line in uci_raw.splitlines():
        if "=wifi-device" in line:
            dev = line.split(".")[1].split("=")[0]
            devices.append(dev)
    devices.sort()

    if devices:
        # Batch: read all radio attributes in one SSH call
        uci_cmds = []
        for dev in devices:
            for attr in ("type", "band", "htmode", "channel", "path"):
                uci_cmds.append(f'echo "$(uci get wireless.{dev}.{attr} 2>/dev/null)"')
        radio_raw = ssh.run(" && ".join(uci_cmds)).strip().splitlines()

        idx = 0
        for dev in devices:
            vals = {}
            for attr in ("type", "band", "htmode", "channel", "path"):
                vals[attr] = radio_raw[idx].strip() if idx < len(radio_raw) else ""
                idx += 1
            radios.append({"device": dev, **vals})

    # WiFi interfaces via iwinfo - run iwinfo on all interfaces in one call
    wifi_interfaces = []
    # Get all interface names and run iwinfo for each in a batch
    iw_script = (
        'for iface in /sys/class/net/*; do '
        'name=$(basename "$iface"); '
        'out=$(iwinfo "$name" info 2>/dev/null); '
        'echo "$out" | grep -q "ESSID:" || continue; '
        'echo "---IFACE:$name---"; '
        'echo "$out"; '
        'done'
    )
    iw_raw = ssh.run(iw_script)

    # Parse the batched output
    current_iface = None
    current_output = []
    for line in iw_raw.splitlines():
        if line.startswith("---IFACE:") and line.endswith("---"):
            if current_iface and current_output:
                wifi_interfaces.append(
                    _parse_iwinfo(current_iface, "\n".join(current_output))
                )
            current_iface = line[len("---IFACE:"):-len("---")]
            current_output = []
        else:
            current_output.append(line)
    if current_iface and current_output:
        wifi_interfaces.append(
            _parse_iwinfo(current_iface, "\n".join(current_output))
        )

    return {
        "radios": radios,
        "interfaces": wifi_interfaces,
    }


def _parse_iwinfo(iface, output):
    """Parse iwinfo output for a single interface."""
    def extract(pattern):
        m = re.search(pattern, output)
        return m.group(1).strip() if m else ""

    mode = extract(r"Mode:\s*(\w+(?:\s\w+)?)\s\s")
    channel = extract(r"Channel:\s*(\d+)")
    freq = extract(r"\((\d+\.\d+)\s*GHz\)")
    hwmode = extract(r"HW Mode\(s\):\s*(.*)")
    txpower = extract(r"Tx-Power:\s*(\d+)")
    hw_name = extract(r"Hardware:\s*.*\[(.+?)\]")

    return {
        "interface": iface,
        "mode": mode,
        "channel": int(channel) if channel.isdigit() else 0,
        "frequency_ghz": freq,
        "hw_modes": hwmode,
        "tx_power_dbm": int(txpower) if txpower.isdigit() else 0,
        "hardware": hw_name,
    }


def collect_thermal(ssh):
    """Thermal sensors from /sys/class/thermal/."""
    script = (
        'for tz in /sys/class/thermal/thermal_zone*; do '
        '[ -d "$tz" ] || continue; '
        'echo "$(cat $tz/type 2>/dev/null)|$(cat $tz/temp 2>/dev/null)"; '
        'done'
    )
    raw = ssh.run(script)
    sensors = []
    for line in raw.strip().splitlines():
        parts = line.split("|")
        if len(parts) >= 2 and parts[0]:
            sensors.append({
                "type": parts[0],
                "temp_millicelsius": int(parts[1]) if parts[1].isdigit() else 0,
            })
    return sensors


def collect_device_tree(ssh):
    """Device tree model and compatible string."""
    model = ssh.read_file("/sys/firmware/devicetree/base/model").replace("\x00", "").strip()
    compat = ssh.read_file("/sys/firmware/devicetree/base/compatible").replace("\x00", ",").strip(",").strip()
    return {"model": model, "compatible": compat}


def collect_board_config(ssh):
    """OpenWrt board.json hardware description."""
    return ssh.run_json("cat /etc/board.json 2>/dev/null")


def collect_leds(ssh):
    """LED inventory from /sys/class/leds/."""
    # Batch: read all LED attributes in one SSH call
    script = (
        'for led in /sys/class/leds/*; do '
        '[ -d "$led" ] || continue; '
        'name=$(basename "$led"); '
        'br=$(cat "$led/brightness" 2>/dev/null); '
        'mx=$(cat "$led/max_brightness" 2>/dev/null); '
        'echo "$name|$br|$mx"; '
        'done'
    )
    raw = ssh.run(script)
    leds = []
    for line in raw.strip().splitlines():
        parts = line.split("|")
        if len(parts) >= 3 and parts[0]:
            leds.append({
                "name": parts[0],
                "brightness": int(parts[1]) if parts[1].isdigit() else 0,
                "max_brightness": int(parts[2]) if parts[2].isdigit() else 0,
            })
    return leds


# --- Snapshot assembly ---

def build_snapshot(ssh):
    """Collect all hardware data and assemble the snapshot."""
    collectors = [
        ("board", collect_board),
        ("system_info", collect_system_info),
        ("cpu", collect_cpu),
        ("memory", collect_memory),
        ("storage", collect_storage),
        ("network", collect_network),
        ("wifi", collect_wifi),
        ("thermal", collect_thermal),
        ("device_tree", collect_device_tree),
        ("board_config", collect_board_config),
        ("leds", collect_leds),
    ]

    data = {}
    for name, fn in collectors:
        logger.info("Collecting %s...", name)
        data[name] = fn(ssh)

    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "type": "Snapshot",
        "uuid": str(uuid.uuid4()),
        "software": SOFTWARE,
        "version": VERSION,
        "data": data,
    }


# --- Upload ---

def upload_snapshot(snapshot_json, url, token):
    """Upload snapshot to DeviceHub using urllib (stdlib)."""
    logger.info("Uploading snapshot to %s...", url)

    data = snapshot_json.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    try:
        import urllib.request
        import urllib.error
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            logger.info("Upload successful (HTTP %s)", resp.status)
            logger.info("Response: %s", body)
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        logger.error("Upload failed (HTTP %s): %s", e.code, body)
        return False
    except urllib.error.URLError as e:
        logger.error("Upload failed: %s", e.reason)
        return False


# --- CLI ---

def parse_args():
    parser = argparse.ArgumentParser(
        description="Hardware snapshot tool for OpenWrt routers. "
                    "Connects via SSH and collects hardware data into a JSON snapshot.",
    )
    parser.add_argument(
        "host",
        help="Router IP or hostname (e.g. 192.168.1.1)",
    )
    parser.add_argument(
        "-u", "--user",
        default="root",
        help="SSH user (default: root)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)",
    )
    parser.add_argument(
        "-i", "--identity",
        help="SSH identity file (private key)",
    )
    parser.add_argument(
        "-o", "--output",
        default="./snapshots",
        help="Output directory for snapshot files (default: ./snapshots)",
    )
    parser.add_argument(
        "--url",
        help="DeviceHub upload URL (e.g. https://example.org/api/v1/snapshot/)",
    )
    parser.add_argument(
        "--token",
        help="DeviceHub auth token",
    )
    parser.add_argument(
        "-s", "--stdout",
        action="store_true",
        help="Print snapshot to stdout only (no file saved)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[workbench] %(message)s",
        stream=sys.stderr,
    )

    logger.info("workbench-openwrt %s", VERSION)

    ssh = OpenWrtSSH(
        host=args.host,
        port=args.port,
        user=args.user,
        identity_file=args.identity,
    )
    ssh.test_connection()

    snapshot = build_snapshot(ssh)
    snapshot_json = json.dumps(snapshot, indent=2)

    if args.stdout:
        print(snapshot_json)
        return

    # Save to file
    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{ts}_{snapshot['uuid']}.json"
    filepath = os.path.join(args.output, filename)

    with open(filepath, "w") as f:
        f.write(snapshot_json)
    logger.info("Snapshot saved to %s", filepath)

    # Upload if configured
    if args.url and args.token:
        upload_snapshot(snapshot_json, args.url, args.token)

    logger.info("Done.")


if __name__ == "__main__":
    main()
