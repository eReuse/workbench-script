# workbench-openwrt

Hardware snapshot tool for OpenWrt routers, part of the [eReuse](https://ereuse.org/) ecosystem.

`workbench-openwrt.py` connects to an OpenWrt device via SSH and collects hardware information, producing a JSON snapshot compatible with [DeviceHub](https://farga.pangea.org/ereuse/devicehub-django/).

## Requirements

- Python 3.6+ on the machine running the script (no pip dependencies -- stdlib only)
- SSH access to the target OpenWrt device
- No extra packages on the router -- uses only base OpenWrt tools (`ubus`, `iwinfo`, `uci`)

## Quick start

### 1. Run the script

```sh
python3 workbench-openwrt.py 192.168.1.1
```

The snapshot JSON is saved to `./snapshots/` by default.

### 2. Print to stdout instead

```sh
python3 workbench-openwrt.py 192.168.1.1 -s
```

### 3. Upload directly to DeviceHub

```sh
python3 workbench-openwrt.py 192.168.1.1 \
  --url https://your-devicehub.example.org/api/v1/snapshot/ \
  --token your-api-token-here
```

## Usage

```
usage: workbench-openwrt.py [-h] [-u USER] [-p PORT] [-i IDENTITY]
                            [-o OUTPUT] [--url URL] [--token TOKEN]
                            [-s] [-v] host

positional arguments:
  host                  Router IP or hostname (e.g. 192.168.1.1)

options:
  -u, --user USER       SSH user (default: root)
  -p, --port PORT       SSH port (default: 22)
  -i, --identity FILE   SSH identity file (private key)
  -o, --output DIR      Output directory (default: ./snapshots)
  --url URL             DeviceHub upload URL
  --token TOKEN         DeviceHub auth token
  -s, --stdout          Print snapshot to stdout only (no file saved)
  -v, --verbose         Enable debug logging
```

## What data is collected

The script collects hardware-only information:

| Category      | Source                  | Description                                       |
|---------------|-------------------------|---------------------------------------------------|
| Board         | `ubus call system board`| Model, hostname, kernel version, OpenWrt release   |
| CPU           | `/proc/cpuinfo`         | Architecture, cores, model, BogoMIPS, flags        |
| Memory        | `/proc/meminfo`         | Total RAM                                          |
| Storage       | `/proc/mtd`, `df`       | Flash/NAND partitions and available space           |
| Network       | `/sys/class/net`        | Ethernet interfaces, MAC addresses, link speed     |
| WiFi          | `iwinfo`                | Radio hardware, supported modes, bands, TX power   |
| Thermal       | `/sys/class/thermal`    | CPU temperature sensors                            |
| Device tree   | `/proc/device-tree`     | SoC compatible string                              |
| LEDs          | `/sys/class/leds`       | Available LED indicators                           |

No user configuration data (passwords, SSIDs, firewall rules, etc.) is collected.

## Example output

After uploading to DeviceHub, a router shows up as:

- **Type**: Router
- **Manufacturer**: Cudy
- **Model**: Cudy WR3000E v1
- **Components**: Processor (Cortex-A53), RAM, Flash storage, Network adapters, WiFi radios

## License

Licensed under [GNU Affero General Public License v3.0](LICENSE).
