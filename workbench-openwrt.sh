#!/bin/ash
# -*- coding: utf-8 -*-

# Copyright (c) 2024 pangea.org Associació Pangea - Coordinadora Comunicació per a la Cooperació
# SPDX-License-Identifier: AGPL-3.0-or-later

# workbench-openwrt.sh - Lightweight hardware snapshot tool for OpenWrt devices
# Designed for resource-constrained routers (ARM/MIPS/etc.)
# Zero dependencies beyond base OpenWrt (ash, ubus, jsonfilter, iwinfo)

VERSION="0.0.1"
SOFTWARE="workbench-script-openwrt"

# --- Configuration ---
# Can be overridden via environment variables or a settings file
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/tmp/snapshots}"
DEVICEHUB_URL="${DEVICEHUB_URL:-}"
DEVICEHUB_TOKEN="${DEVICEHUB_TOKEN:-}"
SETTINGS_FILE="${SETTINGS_FILE:-/etc/workbench.conf}"

# --- Helpers ---

log() {
    logger -t workbench -p daemon.info "$*"
    echo "[workbench] $*" >&2
}

log_err() {
    logger -t workbench -p daemon.err "$*"
    echo "[workbench] ERROR: $*" >&2
}

# Escape a string for safe JSON embedding
json_escape() {
    printf '%s' "$1" | sed \
        -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g' \
        -e 's/	/\\t/g' \
        -e 's/$/\\n/g' | tr -d '\n' | sed 's/\\n$//'
}

# Generate a UUID v4 from the kernel
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# Get current timestamp in ISO-like format
get_timestamp() {
    date -u '+%Y-%m-%d %H:%M:%S'
}

# --- Data Collection Functions ---

# System board info via ubus (model, kernel, release, etc.)
collect_board() {
    ubus call system board 2>/dev/null || echo '{}'
}

# System runtime info (uptime, memory, storage)
collect_system_info() {
    ubus call system info 2>/dev/null || echo '{}'
}

# CPU information from /proc/cpuinfo
collect_cpu() {
    local num_cores
    local cpu_model
    local cpu_arch
    local cpu_features
    local bogomips

    num_cores=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "0")

    # ARM devices typically report differently than x86
    cpu_model=$(grep -m1 'model name\|Hardware\|CPU part' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //')
    cpu_arch=$(grep -m1 'CPU architecture' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //')
    cpu_features=$(grep -m1 'Features\|flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //')
    bogomips=$(grep -m1 'BogoMIPS' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //')

    # CPU frequency if available
    local cpu_freq_max=""
    [ -f /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ] && \
        cpu_freq_max=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)

    cat <<-CPUJSON
	{
	    "num_cores": ${num_cores},
	    "model": "$(json_escape "$cpu_model")",
	    "architecture": "$(json_escape "$cpu_arch")",
	    "features": "$(json_escape "$cpu_features")",
	    "bogomips": "$(json_escape "$bogomips")",
	    "max_freq_khz": "${cpu_freq_max:-null}"
	}
	CPUJSON
}

# Memory info
collect_memory() {
    local mem_total mem_free mem_available
    mem_total=$(awk '/^MemTotal/ {print $2}' /proc/meminfo 2>/dev/null)
    mem_free=$(awk '/^MemFree/ {print $2}' /proc/meminfo 2>/dev/null)
    mem_available=$(awk '/^MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null)

    cat <<-MEMJSON
	{
	    "total_kb": ${mem_total:-0},
	    "free_kb": ${mem_free:-0},
	    "available_kb": ${mem_available:-0}
	}
	MEMJSON
}

# Flash / storage partitions from /proc/mtd and UBI
collect_storage() {
    local mtd_json=""
    local first=1

    # MTD partitions
    if [ -f /proc/mtd ]; then
        while IFS= read -r line; do
            # skip header
            case "$line" in dev:*) continue ;; esac

            local dev size erasesize name
            dev=$(echo "$line" | awk '{print $1}' | tr -d ':')
            size=$(echo "$line" | awk '{print $2}')
            erasesize=$(echo "$line" | awk '{print $3}')
            name=$(echo "$line" | awk '{print $4}' | tr -d '"')

            # Convert hex size to decimal
            size_dec=$((0x$size))

            [ "$first" -eq 1 ] && first=0 || mtd_json="${mtd_json},"
            mtd_json="${mtd_json}{\"device\":\"${dev}\",\"name\":\"${name}\",\"size_bytes\":${size_dec},\"erasesize\":\"0x${erasesize}\"}"
        done < /proc/mtd
    fi

    # UBI volumes
    local ubi_json=""
    first=1
    if command -v ubinfo >/dev/null 2>&1; then
        local vol_id
        for vol_dir in /sys/class/ubi/ubi0_*; do
            [ -d "$vol_dir" ] || continue
            vol_id=$(basename "$vol_dir")
            local vol_name vol_size vol_type
            vol_name=$(cat "${vol_dir}/name" 2>/dev/null)
            vol_size=$(cat "${vol_dir}/data_bytes" 2>/dev/null)
            vol_type=$(cat "${vol_dir}/type" 2>/dev/null)

            [ "$first" -eq 1 ] && first=0 || ubi_json="${ubi_json},"
            ubi_json="${ubi_json}{\"id\":\"${vol_id}\",\"name\":\"${vol_name}\",\"size_bytes\":${vol_size:-0},\"type\":\"${vol_type}\"}"
        done
    fi

    # Filesystem usage
    local fs_json=""
    first=1
    df -k 2>/dev/null | while IFS= read -r line; do
        case "$line" in Filesystem*) continue ;; esac
        local fs size used avail pct mount
        fs=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $2}')
        used=$(echo "$line" | awk '{print $3}')
        avail=$(echo "$line" | awk '{print $4}')
        pct=$(echo "$line" | awk '{print $5}')
        mount=$(echo "$line" | awk '{print $6}')

        [ "$first" -eq 1 ] && first=0 || printf ','
        printf '{"filesystem":"%s","size_kb":%s,"used_kb":%s,"available_kb":%s,"use_percent":"%s","mount":"%s"}' \
            "$fs" "${size:-0}" "${used:-0}" "${avail:-0}" "$pct" "$mount"
    done > /tmp/.wb_fs_json 2>/dev/null
    fs_json=$(cat /tmp/.wb_fs_json 2>/dev/null)
    rm -f /tmp/.wb_fs_json

    cat <<-STORJSON
	{
	    "mtd": [${mtd_json}],
	    "ubi": [${ubi_json}],
	    "filesystems": [${fs_json}]
	}
	STORJSON
}

# Network interfaces (physical ports, bridges, MACs)
collect_network() {
    local ifaces_json=""
    local first=1

    for iface_path in /sys/class/net/*; do
        local iface
        iface=$(basename "$iface_path")

        # Skip loopback
        [ "$iface" = "lo" ] && continue

        local mac operstate mtu type speed
        mac=$(cat "${iface_path}/address" 2>/dev/null)
        operstate=$(cat "${iface_path}/operstate" 2>/dev/null)
        mtu=$(cat "${iface_path}/mtu" 2>/dev/null)
        type=$(cat "${iface_path}/type" 2>/dev/null)
        speed=$(cat "${iface_path}/speed" 2>/dev/null)

        [ "$first" -eq 1 ] && first=0 || ifaces_json="${ifaces_json},"
        ifaces_json="${ifaces_json}{\"name\":\"${iface}\",\"mac\":\"${mac}\",\"state\":\"${operstate}\",\"mtu\":${mtu:-0}"
        [ -n "$speed" ] && [ "$speed" != "-1" ] && \
            ifaces_json="${ifaces_json},\"speed_mbps\":${speed}"
        ifaces_json="${ifaces_json}}"
    done

    printf '{"interfaces":[%s]}' "$ifaces_json"
}

# WiFi radio information via iwinfo and ubus
collect_wifi() {
    local radios_json=""
    local first=1

    # Enumerate wifi devices from uci
    local devices
    devices=$(uci show wireless 2>/dev/null | grep '=wifi-device' | cut -d. -f2 | cut -d= -f1)

    for dev in $devices; do
        local dev_type band htmode channel path
        dev_type=$(uci get "wireless.${dev}.type" 2>/dev/null)
        band=$(uci get "wireless.${dev}.band" 2>/dev/null)
        htmode=$(uci get "wireless.${dev}.htmode" 2>/dev/null)
        channel=$(uci get "wireless.${dev}.channel" 2>/dev/null)
        path=$(uci get "wireless.${dev}.path" 2>/dev/null)

        [ "$first" -eq 1 ] && first=0 || radios_json="${radios_json},"
        radios_json="${radios_json}{\"device\":\"${dev}\",\"type\":\"${dev_type}\",\"band\":\"${band}\",\"htmode\":\"${htmode}\",\"channel\":\"${channel}\",\"path\":\"$(json_escape "$path")\"}"
    done

    # WiFi interfaces and their details via iwinfo
    local wifi_ifaces_json=""
    first=1

    for iface_path in /sys/class/net/*; do
        local iface
        iface=$(basename "$iface_path")

        # Check if it's a real wireless interface by looking for ESSID in output
        # (iwinfo returns 0 for ALL interfaces on OpenWrt, so check content)
        local iw_output
        iw_output=$(iwinfo "$iface" info 2>/dev/null)
        echo "$iw_output" | grep -q 'ESSID:' || continue

        local ssid mode channel freq hwmode txpower
        ssid=$(echo "$iw_output" | grep 'ESSID:' | sed 's/.*ESSID: *"\(.*\)"/\1/')
        mode=$(echo "$iw_output" | grep 'Mode:' | sed 's/.*Mode: *\([A-Za-z]*\( [A-Za-z]*\)\?\)  .*/\1/')
        channel=$(echo "$iw_output" | grep 'Channel:' | sed 's/.*Channel: *\([0-9]*\).*/\1/')
        freq=$(echo "$iw_output" | grep 'Channel:' | sed 's/.*(\([0-9.]*\) GHz).*/\1/')
        hwmode=$(echo "$iw_output" | grep 'HW Mode' | sed 's/.*HW Mode(s): *\(.*\)/\1/')
        txpower=$(echo "$iw_output" | grep 'Tx-Power:' | sed 's/.*Tx-Power: *\([0-9]*\).*/\1/')

        local hw_name
        hw_name=$(echo "$iw_output" | grep 'Hardware:' | sed 's/.*\[\(.*\)\]/\1/')

        [ "$first" -eq 1 ] && first=0 || wifi_ifaces_json="${wifi_ifaces_json},"
        wifi_ifaces_json="${wifi_ifaces_json}{\"interface\":\"${iface}\",\"ssid\":\"$(json_escape "$ssid")\",\"mode\":\"${mode}\",\"channel\":${channel:-0},\"frequency_ghz\":\"${freq}\",\"hw_modes\":\"$(json_escape "$hwmode")\",\"tx_power_dbm\":${txpower:-0},\"hardware\":\"$(json_escape "$hw_name")\"}"
    done

    # Connected clients
    local clients_json=""
    first=1

    for iface_path in /sys/class/net/*; do
        local iface
        iface=$(basename "$iface_path")

        # Same wireless check as above
        iwinfo "$iface" info 2>/dev/null | grep -q 'ESSID:' || continue

        local assoc_output
        assoc_output=$(iwinfo "$iface" assoclist 2>/dev/null)
        [ -z "$assoc_output" ] && continue

        echo "$assoc_output" | while IFS= read -r line; do
            case "$line" in
                *"dBm"*)
                    local client_mac signal
                    client_mac=$(echo "$line" | awk '{print $1}')
                    signal=$(echo "$line" | sed 's/.*\(-[0-9]*\) dBm.*/\1/' | head -c 4)
                    [ "$first" -eq 1 ] && first=0 || printf ','
                    printf '{"mac":"%s","interface":"%s","signal_dbm":%s}' \
                        "$client_mac" "$iface" "${signal:-0}"
                    ;;
            esac
        done > /tmp/.wb_clients 2>/dev/null
    done
    clients_json=$(cat /tmp/.wb_clients 2>/dev/null)
    rm -f /tmp/.wb_clients

    cat <<-WIFIJSON
	{
	    "radios": [${radios_json}],
	    "interfaces": [${wifi_ifaces_json}],
	    "connected_clients": [${clients_json}]
	}
	WIFIJSON
}

# Thermal sensors
collect_thermal() {
    local thermal_json=""
    local first=1

    for tz in /sys/class/thermal/thermal_zone*; do
        [ -d "$tz" ] || continue
        local type temp
        type=$(cat "${tz}/type" 2>/dev/null)
        temp=$(cat "${tz}/temp" 2>/dev/null)

        [ "$first" -eq 1 ] && first=0 || thermal_json="${thermal_json},"
        thermal_json="${thermal_json}{\"type\":\"${type}\",\"temp_millicelsius\":${temp:-0}}"
    done

    printf '[%s]' "$thermal_json"
}

# Board.json (OpenWrt hardware description file)
collect_board_json() {
    if [ -f /etc/board.json ]; then
        cat /etc/board.json
    else
        echo '{}'
    fi
}

# Device tree info
collect_devicetree() {
    local model compat
    model=$(cat /sys/firmware/devicetree/base/model 2>/dev/null | tr -d '\0')
    compat=$(cat /sys/firmware/devicetree/base/compatible 2>/dev/null | tr '\0' ',' | sed 's/,$//')

    printf '{"model":"%s","compatible":"%s"}' \
        "$(json_escape "$model")" "$(json_escape "$compat")"
}

# LED inventory
collect_leds() {
    local leds_json=""
    local first=1

    for led in /sys/class/leds/*; do
        [ -d "$led" ] || continue
        local name brightness max_brightness
        name=$(basename "$led")
        brightness=$(cat "${led}/brightness" 2>/dev/null)
        max_brightness=$(cat "${led}/max_brightness" 2>/dev/null)

        [ "$first" -eq 1 ] && first=0 || leds_json="${leds_json},"
        leds_json="${leds_json}{\"name\":\"${name}\",\"brightness\":${brightness:-0},\"max_brightness\":${max_brightness:-0}}"
    done

    printf '[%s]' "$leds_json"
}

# --- Snapshot Assembly ---

build_snapshot() {
    local uuid timestamp
    uuid=$(generate_uuid)
    timestamp=$(get_timestamp)

    log "Collecting hardware data..."

    log "  -> board info"
    local board
    board=$(collect_board)

    log "  -> system info"
    local sysinfo
    sysinfo=$(collect_system_info)

    log "  -> CPU"
    local cpu
    cpu=$(collect_cpu)

    log "  -> memory"
    local memory
    memory=$(collect_memory)

    log "  -> storage"
    local storage
    storage=$(collect_storage)

    log "  -> network"
    local network
    network=$(collect_network)

    log "  -> WiFi"
    local wifi
    wifi=$(collect_wifi)

    log "  -> thermal"
    local thermal
    thermal=$(collect_thermal)

    log "  -> device tree"
    local dtree
    dtree=$(collect_devicetree)

    log "  -> board.json"
    local boardjson
    boardjson=$(collect_board_json)

    log "  -> LEDs"
    local leds
    leds=$(collect_leds)

    # Compose the final JSON snapshot
    cat <<-SNAPSHOT
	{
	    "timestamp": "${timestamp}",
	    "type": "Snapshot",
	    "uuid": "${uuid}",
	    "software": "${SOFTWARE}",
	    "version": "${VERSION}",
	    "data": {
	        "board": ${board},
	        "system_info": ${sysinfo},
	        "cpu": ${cpu},
	        "memory": ${memory},
	        "storage": ${storage},
	        "network": ${network},
	        "wifi": ${wifi},
	        "thermal": ${thermal},
	        "device_tree": ${dtree},
	        "board_config": ${boardjson},
	        "leds": ${leds}
	    }
	}
	SNAPSHOT
}

# --- Upload ---

upload_snapshot() {
    local snapshot_file="$1"

    if [ -z "$DEVICEHUB_URL" ]; then
        log "No DEVICEHUB_URL configured, skipping upload."
        return 0
    fi

    log "Uploading snapshot to ${DEVICEHUB_URL}..."

    local response=""
    local rc=0

    if command -v curl >/dev/null 2>&1; then
        response=$(curl -s -w "\n%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${DEVICEHUB_TOKEN}" \
            -d @"${snapshot_file}" \
            "${DEVICEHUB_URL}" 2>&1) || rc=$?
    elif command -v wget >/dev/null 2>&1; then
        # OpenWrt uses uclient-fetch (aliased as wget) which supports --post-file
        response=$(wget -q \
            --header="Content-Type: application/json" \
            --header="Authorization: Bearer ${DEVICEHUB_TOKEN}" \
            --post-file="${snapshot_file}" \
            -O - \
            "${DEVICEHUB_URL}" 2>&1) || rc=$?
    else
        log_err "No HTTP client available (curl or wget). Cannot upload."
        return 1
    fi

    if [ "$rc" -eq 0 ]; then
        log "Upload successful."
        [ -n "$response" ] && log "Server response: ${response}"
    else
        log_err "Upload failed (exit code ${rc})."
        [ -n "$response" ] && log_err "Response: ${response}"
    fi

    return $rc
}

# --- Main ---

load_settings() {
    if [ -f "$SETTINGS_FILE" ]; then
        log "Loading settings from ${SETTINGS_FILE}"
        . "$SETTINGS_FILE"
    fi
}

usage() {
    cat <<-USAGE
	Usage: $(basename "$0") [OPTIONS]

	Lightweight hardware snapshot tool for OpenWrt devices.

	Options:
	  -o DIR        Output directory (default: /tmp/snapshots)
	  -u URL        DeviceHub upload URL
	  -t TOKEN      DeviceHub auth token
	  -c FILE       Settings file (default: /etc/workbench.conf)
	  -s            Print snapshot to stdout only (no file saved)
	  -h            Show this help

	Environment variables:
	  SNAPSHOT_DIR, DEVICEHUB_URL, DEVICEHUB_TOKEN, SETTINGS_FILE

	USAGE
    exit 0
}

main() {
    local stdout_only=0

    while [ $# -gt 0 ]; do
        case "$1" in
            -o) SNAPSHOT_DIR="$2"; shift 2 ;;
            -u) DEVICEHUB_URL="$2"; shift 2 ;;
            -t) DEVICEHUB_TOKEN="$2"; shift 2 ;;
            -c) SETTINGS_FILE="$2"; shift 2 ;;
            -s) stdout_only=1; shift ;;
            -h|--help) usage ;;
            *) log_err "Unknown option: $1"; usage ;;
        esac
    done

    load_settings

    log "workbench-openwrt ${VERSION} starting..."

    local snapshot
    snapshot=$(build_snapshot)

    if [ "$stdout_only" -eq 1 ]; then
        echo "$snapshot"
        return 0
    fi

    # Save to file
    mkdir -p "$SNAPSHOT_DIR"
    local ts_file uuid_short filename
    ts_file=$(date -u '+%Y-%m-%d_%H-%M-%S')
    uuid_short=$(echo "$snapshot" | jsonfilter -e '@.uuid' 2>/dev/null)
    filename="${ts_file}_${uuid_short:-unknown}.json"
    local filepath="${SNAPSHOT_DIR}/${filename}"

    echo "$snapshot" > "$filepath"
    log "Snapshot saved to ${filepath}"

    # Upload if configured
    upload_snapshot "$filepath"

    log "Done."
    echo "$filepath"
}

main "$@"
