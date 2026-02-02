# -*- coding: utf-8 -*-

# Copyright (c) 2024 pangea.org Associació Pangea - Coordinadora Comunicació per a la Cooperació
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import glob
import json
import uuid
import hashlib
import argparse
import configparser
import urllib.parse
import urllib.request
import urllib.error

import gettext
import locale
import logging

from datetime import datetime
import time

# ANSI Colors
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BOLD = "\033[1m"
C_END = "\033[0m"

SNAPSHOT_BASE = {
    'timestamp': "",
    'type': 'Snapshot',
    'uuid': "",
    'software': "workbench-script",
    'version': "0.0.1",
    'operator_id': "",
    'data': {},
    'erase': []
}

## UI Helpers ##

def print_header(text):
    print(f"\n{C_BOLD}{'='*60}{C_END}")
    print(f"{C_BOLD}{text.center(60)}{C_END}")
    print(f"{C_BOLD}{'='*60}{C_END}")

def print_success(text):
    print(f"{C_GREEN}{text}{C_END}")

def print_warning(text):
    print(f"{C_YELLOW}{text}{C_END}")

def print_error(text):
    print(f"{C_RED}{text}{C_END}")

def ask_user(question, default="n"):
    prompt = " [Y/n]" if default == "y" else " [y/N]"
    while True:
        sys_response = input(f"\n{C_BOLD}{question}{prompt}{C_END}: ").strip().lower()
        if not sys_response:
            return True if default == "y" else False
        if sys_response in ['y', 'yes', 's', 'si']:
            return True
        if sys_response in ['n', 'no']:
            return False
        print_warning(_("Please enter 'y' or 'n'."))

## Utility Functions ##
def logs(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as err:
            logger.error(err)
            return ''

    return wrapper


@logs
def exec_cmd(cmd):
    logger.info(_('Running command `%s`'), cmd)
    return os.popen(cmd).read()


@logs
def exec_cmd_erase(cmd):
    logger.info(_('Running command `%s`'), cmd)
    return ''
    # return os.popen(cmd).read()

## End Utility functions ##


## Legacy Functions ##

def convert_to_legacy_snapshot(snapshot):
    snapshot["sid"] = str(uuid.uuid4()).split("-")[1]
    snapshot["software"] = "workbench-script"
    snapshot["version"] = "dev"
    snapshot["schema_api"] = "1.0.0"
    snapshot["settings_version"] = "No Settings Version (NaN)"
    snapshot["timestamp"] = snapshot["timestamp"].replace(" ", "T")
    snapshot["data"]["smart"] = json.loads(snapshot["data"]["smartctl"])
    snapshot["data"].pop("smartctl")
    snapshot["data"].pop("inxi")
    snapshot.pop("operator_id")
    snapshot.pop("erase")

    lshw = 'sudo lshw -json'
    hwinfo = 'sudo hwinfo --reallyall'
    lspci = 'sudo lspci -vv'

    data = {
        'lshw': exec_cmd(lshw) or "{}",
        'hwinfo': exec_cmd(hwinfo),
        'lspci': exec_cmd(lspci)
    }
    snapshot['data'].update(data)

## End Legacy Functions ##


## Command Functions ##
## Erase Functions ##
## Xavier Functions ##
def erase_basic(disk):
    """
    Basic Erasure
    https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=917935

    Settings for basic data erasure using shred Linux command.
    A software-based fast non-100%-secured way of erasing data storage.

    Performs 1 pass overwriting one round using all zeros.
    Compliant with NIST SP-800-8y8.

    In settings appear:

    WB_ERASE = EraseBasic
    WB_ERASE_STEPS = 1
    WB_ERASE_LEADING_ZEROS = False

    """
    cmd = f'shred -vn 1 /dev/{disk}'
    return [exec_cmd_erase(cmd)]


def erase_baseline(disk):
    """
    Baseline Secure Erasure
    Settings for advanced data erasure using badblocks Linux software.
    A secured-way of erasing data storages, erase hidden areas,
    checking the erase sector by sector.

    Performs 1 pass overwriting each sector with zeros and a final verification.
    Compliant with HMG Infosec Standard 5 Baseline.

    In settings appear:

    WB_ERASE = EraseSectors
    WB_ERASE_STEPS = 1
    WB_ERASE_LEADING_ZEROS = True

    WB_ERASE_1_METHOD = EraseBasic
    WB_ERASE_1_STEP_TYPE = 0
    WB_ERASE_2_METHOD = EraseSectors
    WB_ERASE_2_STEP_TYPE = 1
    """
    result = []
    cmd = f'shred -zvn 0 /dev/{disk}'
    result.append(exec_cmd_erase(cmd))
    cmd = f'badblocks -st random -w /dev/{disk}'
    result.append(exec_cmd_erase(cmd))
    return result


def erase_enhanced(disk):
    """
    Enhanced Secure Erasure
    Settings for advanced data erasure using badblocks Linux software.
    A secured-way of erasing data storages, erase hidden areas,
    checking the erase sector by sector.

    Performs 3 passes overwriting every sector with zeros and ones,
    and final verification. Compliant with HMG Infosec Standard 5 Enhanced.

    In settings appear:

    WB_ERASE = EraseSectors
    WB_ERASE_LEADING_ZEROS = True

    WB_ERASE_1_METHOD = EraseBasic
    WB_ERASE_1_STEP_TYPE = 1
    WB_ERASE_2_METHOD = EraseBasic
    WB_ERASE_2_STEP_TYPE = 0
    WB_ERASE_3_METHOD = EraseSectors
    WB_ERASE_3_STEP_TYPE = 1
    """
    result = []
    cmd = f'shred -vn 1 /dev/{disk}'
    result.append(exec_cmd_erase(cmd))
    cmd = f'shred -zvn 0 /dev/{disk}'
    result.append(exec_cmd_erase(cmd))
    ## creo que realmente seria asi (3 pases y una extra poniendo a ceros):
    # shred -zvn 3 /def/{disk}
    # tampoco estoy seguro que el badblocks haga un proceso de verificacion.
    cmd = f'badblocks -st random -w /dev/{disk}'
    result.append(exec_cmd_erase(cmd))
    return result

## End Xavier Functions ##

def ata_secure_erase_null(disk):
    cmd_baseline = f'hdparm --user-master u --security-erase NULL /dev/{disk}'
    return [exec_cmd_erase(cmd_baseline)]


def ata_secure_erase_enhanced(disk):
    cmd_enhanced = f'hdparm --user-master u --security-erase-enhanced /dev/{disk}'
    return [exec_cmd_erase(cmd_enhanced)]


def nvme_secure_erase(disk):
    cmd_encrypted = f'nvme format /dev/{disk} --ses=1'
    return [exec_cmd_erase(cmd_encrypted)]


## End Erase Functions ##

@logs
def get_disks():
    disks = json.loads(
        exec_cmd('lsblk -Jdo NAME,TYPE,MOUNTPOINTS,ROTA,TRAN,MODEL,SIZE')
    )
    return disks.get('blockdevices', [])

@logs
def gen_erase(all_disks, type_erase, user_disk=None):
    erase = []
    for disk in all_disks:
        if user_disk and disk['name'] not in user_disk:
            continue

        if disk['type'] != 'disk':
            continue

        if 'boot' in disk['mountpoints']:
            continue

        if not disk['rota']:
            # if soport nvme erase
            erase.append(nvme_secure_erase(disk['name']))
        elif disk['tran'] in ['ata', 'sata']:
            # if soport ata erase
            if type_erase == 'basic':
                erase.append(ata_secure_erase_null(disk['name']))
            elif type_erase == 'baseline':
                erase.append(ata_secure_erase_null(disk['name']))
            elif type_erase == 'enhanced':
                erase.append(ata_secure_erase_enhanced(disk['name']))
        else:
            # For old disks
            if type_erase == 'basic':
                erase.append(erase_basic(disk['name']))
            elif type_erase == 'baseline':
                erase.append(erase_baseline(disk['name']))
            elif type_erase == 'enhanced':
                erase.append(erase_enhanced(disk['name']))
    return erase


@logs
def exec_smart(disk):
    cmd = f'sudo smartctl -x --json=cosviu /dev/{disk}'
    return json.loads(exec_cmd(cmd))


@logs
def smartctl(all_disks, disk=None):

    if disk:
        return [exec_smart(disk)]

    data_list = []
    for disk in all_disks:
        if disk['type'] == 'disk':
            data = exec_smart(disk['name'])
            data_list.append(data)

    return json.dumps(data_list)

## End Command Functions ##


# TODO permitir selección
# TODO permitir que vaya más rápido
def collect_device_data(all_disks):
    dmidecode = 'sudo dmidecode'
    inxi = "sudo inxi -afmnGEMABD -x 3 --edid --output json --output-file print"
    return {
        'smartctl': smartctl(all_disks),
        'dmidecode': exec_cmd(dmidecode),
        'inxi': exec_cmd(inxi),
        'snapshot_type': "Device",
    }


def collect_display_data(display):
    edid_decode = f'sudo edid-decode -s -n {display["edid_path"]}'
    return {
        'edid_hex': display["edid_hex"],
        'edid_decode': exec_cmd(edid_decode),
        'snapshot_type': "Display",
    }


def collect_disk_data(disk):
    _smart_output = exec_cmd(f"sudo smartctl -a -j /dev/{disk.get('name')}")
    _lsblk_output = exec_cmd(f"lsblk -o NAME,SIZE,MODEL,SERIAL,TRAN,ROTA,MOUNTPOINTS -J /dev/{disk.get('name')}" )

    return {
        "smartctl":json.loads(_smart_output),
        "lsblk": json.loads(_lsblk_output),
        "snapshot_type": "Disk",
    }


def gen_device_snapshot(config):
    legacy = config.get("legacy", None)

    all_disks = get_disks()
    erase_data = None
    if config['erase'] and config['device'] and not legacy:
        erase_data = gen_erase(all_disks, config['erase'], user_disk=config['device'])
    elif config['erase'] and not legacy:
        erase_data = gen_erase(all_disks, config['erase'])

    data = collect_device_data(all_disks)
    if erase_data:
        data['erase'] = erase_data

    # legacy snapshots aren't sent to idhub
    snap, uuid = create_snapshot(data, config, sign=not legacy)
    if legacy:
        convert_to_legacy_snapshot(snap)

    return snap, uuid


def gen_display_snapshot(display, config):
    data = collect_display_data(display)
    return create_snapshot(data, config, sign= False)

def gen_disk_snapshot(disk, config):
    data = collect_disk_data(disk)
    return create_snapshot(data, config, sign=False)

def create_snapshot(data, config, sign=True):
    snapshot = SNAPSHOT_BASE.copy()
    snap_uuid = str(uuid.uuid4())
    snapshot.update({
        "timestamp": str(datetime.now()),
        "uuid": snap_uuid,
        "data": data,
    })

    wb_sign_token = config.get("wb_sign_token")
    if wb_sign_token:
        tk = wb_sign_token.encode("utf8")
        snapshot["operator_id"] = hashlib.sha3_256(tk).hexdigest()

    if sign and wb_sign_token and config.get("url_wallet"):
        return send_snapshot_to_idhub(snapshot, wb_sign_token, config["url_wallet"]), snap_uuid

    return snapshot, snap_uuid


def send_snapshot(snapshot_json, snap_uuid, config):
    print_header(_("Sending snapshot {} \nto {}".format(snap_uuid, config['url'])))
    legacy = config.get("legacy", None)
    disable_qr = config.get("disable_qr", None)

    if config.get('url'):
        send_snapshot_to_devicehub(
            snapshot_json,
            config['token'],
            config['url'],
            snap_uuid,
            legacy,
            disable_qr
        )


def save_snapshot_in_disk(snapshot_dict, snap_uuid, config):
    snapshot_json = json.dumps(snapshot_dict)
    path = config['path']
    snapshot_path = os.path.join(path, 'snapshots')

    filename = "{}/{}_{}.json".format(
        snapshot_path,
        datetime.now().strftime("%Y%m%d-%H_%M_%S"),
        snap_uuid)

    try:
        if not os.path.exists(snapshot_path):
            os.makedirs(snapshot_path)
            logger.info(_("Created snapshots directory at '%s'"), snapshot_path)
        with open(filename, "w") as f:
            f.write(snapshot_json)
        logger.info(_("Snapshot written in path '%s'"), filename)
        return snapshot_json
    except Exception as e:
        try:
            logger.warning(_("Attempting to save file in actual path. Reason: Failed to write in snapshots directory:\n    %s."), e)
            fallback_filename = "{}/{}_{}.json".format(
                path,
                datetime.now().strftime("%Y%m%d-%H_%M_%S"),
                snap_uuid)
            with open(fallback_filename, "w") as f:
                f.write(snapshot_json)
                logger.warning(_("Snapshot written in fallback path '%s'"), fallback_filename)
                return snapshot_json
        except Exception as e:
            logger.error(_("Could not save snapshot locally. Reason: Failed to write in fallback path:\n    %s"), e)

def http_post(url, data, headers, redirect_depth=0):
    """Send a POST request with given headers and JSON data."""

    MAX_REDIRECTS = 5
    if redirect_depth > MAX_REDIRECTS:
        err_msg = "Error: Too many redirects (limit {})".format(MAX_REDIRECTS)
        logger.error(err_msg)
        return 0, err_msg
    try:
        request = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(request) as response:
            status_code = response.getcode()
            response_text = response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 307, 308):
            new_location = e.headers.get('Location')
            if new_location:
                new_url = urllib.parse.urljoin(url, new_location)
                logger.info(_("Redirect %s detected. Retrying POST to: %s"), e.code, new_url)
                return http_post(new_url, data, headers, redirect_depth + 1)
    except urllib.error.HTTPError as e:
        status_code = e.code
        response_text = e.read().decode('utf-8')
        logger.error("HTTPError %s: %s", status_code, response_text)
    return status_code, response_text

def send_snapshot_to_idhub(snapshot, token, url):
    """Send snapshot to be signed as a credential"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        cred = {
            "type": "DeviceSnapshotV1",
            "save": False,
            "data": {
                "operator_id": snapshot["operator_id"],
                "dmidecode": snapshot["data"]["dmidecode"],
                "inxi": snapshot["data"]["inxi"],
                "smartctl": snapshot["data"]["smartctl"],
                "uuid": snapshot["uuid"],
            }
        }

        data = json.dumps(cred).encode('utf-8')

        ## uncomment to save precredential
        #with open('/tmp/pre-vc-test.json', "wb") as f:
        #    f.write(data)

        status_code, response_text = http_post(url, data, headers)

        if 200 <= status_code < 300:
            logger.info(_("Credential successfully signed"))
            res = json.loads(response_text)
            if res.get("status") == "success" and res.get("data"):
                return res["data"]
            return snapshot
        else:
            logger.error(_("Failed to sign credential. URL: '%s'"), url)
            return snapshot

    except Exception as e:
        logger.error(_("Credential not remotely signed by IdHub URL '%s'. Do you have internet? Is your server up & running? Is the url token authorized?\n    %s"), url, e)
        return snapshot

# apt install qrencode
def generate_qr_code(url, disable_qr):
    """Generate and print QR code for the given URL."""
    if disable_qr:
        return
    qr_command = "echo {} | qrencode -t ANSI".format(url)
    print(exec_cmd(qr_command))

# TODO sanitize url, if url is like this, it fails
#   url = 'http://127.0.0.1:8000/api/snapshot/'
    """Send snapshot to be stored in devicehub inventory service"""
def send_snapshot_to_devicehub(snapshot_json, token, url, ev_uuid, legacy, disable_qr, http_max_retries=5, http_retry_delay=5):
    url_components = urllib.parse.urlparse(url)
    ev_path = f"evidence/{ev_uuid}"
    components = (url_components.scheme, url_components.netloc, ev_path, '', '', '')
    ev_url = urllib.parse.urlunparse(components)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    retries = 1
    while retries <= http_max_retries:
        try:
            data = snapshot_json.encode('utf-8')
            status_code, response_text = http_post(url, data, headers)

            if 200 <= status_code < 300:
                logger.info(_("Snapshot successfully sent to '%s'"), url)
                return True
                if legacy:
                    try:
                        response = json.loads(response_text)
                        public_url = response.get('public_url')
                        dhid = response.get('dhid')
                        if public_url:
                            generate_qr_code(public_url, disable_qr)
                            print("url: {}".format(public_url))
                        if dhid:
                            print("dhid: {}".format(dhid))
                    except Exception:
                        logger.error(response_text)
                else:
                    generate_qr_code(ev_url, disable_qr)
                    print("url: {}".format(ev_url))
                return
            else:
                logger.error(
                    _("Snapshot %s not remotely sent to URL '%s'. Server responded with error:\n  %s"), ev_uuid, url, response_text)
        except Exception as e:
            logger.error(
                _("Snapshot not remotely sent to URL '%s'. Do you have internet? Is your server up & running? Is the url token authorized?\n    %s"), url, e)

        retries += 1
        if retries <= http_max_retries:
            logger.info(_("Retrying... (%d/%d)"), retries, http_max_retries)
            time.sleep(http_retry_delay)

    logger.error(
        _("Failed to send snapshot to URL '%s' after %d attempts"), url, http_max_retries)
    return False


def load_config(config_file="settings.ini"):
    """
    Tries to load configuration from a config file.
    """
    config = configparser.ConfigParser()

    if os.path.exists(config_file):
        # If config file exists, read from it

        logger.info(_("Found config file in path: %s."), config_file)
        config.read(config_file)
        path = config.get('settings', 'path', fallback=os.getcwd())
        # TODO validate that has http:// start
        url = config.get('settings', 'url', fallback=None)
        token = config.get('settings', 'token', fallback=None)
        # TODO validate that the device exists?
        device = config.get('settings', 'device', fallback=None)
        erase = config.get('settings', 'erase', fallback=None)
        legacy = config.get('settings', 'legacy', fallback=None)
        url_wallet = config.get('settings', 'url_wallet', fallback=None)
        wb_sign_token = config.get('settings', 'wb_sign_token', fallback=None)
        disable_qr = config.get('settings', 'disable_qr', fallback=None)
        http_max_retries = int(config.get('settings', 'http_max_retries', fallback=1))
        http_retry_delay = int(config.get('settings', 'http_retry_delay', fallback=5))
        display_server = config.get('settings', "display_server", fallback=None)
        disk_server = config.get('settings', "disk_server", fallback=None)
    else:
        logger.error(_("Config file '%s' not found. Using default values."), config_file)
        path = os.path.join(os.getcwd())
        url, token, device, erase, legacy, url_wallet, wb_sign_token, disable_qr, display_server, disk_server = (None,)*10

    return {
        'path': path,
        'url': url,
        'token': token,
        'device': device,
        'erase': erase,
        'display_server': display_server,
        'disk_server': disk_server,
        'legacy': legacy,
        'wb_sign_token': wb_sign_token,
        'url_wallet': url_wallet,
        'disable_qr': disable_qr,
        'http_max_retries': http_max_retries,
        'http_retry_delay': http_retry_delay
    }

def parse_args():
    """
    Parse config argument, if available
    """
    parser = argparse.ArgumentParser(
        usage=_("workbench-script.py [-h] [--config CONFIG]"),
        description=_("Optional config loader for workbench."))
    parser.add_argument(
        '--config',
        help=_("path to the config file. Defaults to 'settings.ini' in the current directory."),
        default="settings.ini"  # Fallback to 'settings.ini' by default
    )
    return parser.parse_args()

def prepare_lang():
    locale_path = os.path.join(os.path.dirname(__file__), 'locale')
    domain = 'messages'
    gettext.bindtextdomain(domain, locale_path)
    gettext.textdomain(domain)
    global _
    # with LANG=es_ES.UTF-8, it detects spanish
    _ = gettext.gettext
    # # this would force it to spanish
    # lang = gettext.translation(domain, localedir=locale_path, languages=['es'])
    # lang.install()
    # _ = lang.gettext

def prepare_logger():
    global logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] workbench: %(levelname)s: %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

def get_displays():
    displays = []

    #https://askubuntu.com/questions/81370/how-to-create-extract-the-edid-for-from-a-monitor
    for edid_file in glob.glob("/sys/class/drm/*/edid"):
        connector_dir = os.path.dirname(edid_file)
        status_file = os.path.join(connector_dir, "status")

        connector_name = os.path.basename(connector_dir)

        status = None
        if os.path.isfile(status_file):
            try:
                with open(status_file, "r") as f:
                    status = f.read().strip()
            except Exception as e:
                print_error(_("Error reading {}: {}").format(status_file, e))

        if status == "connected":
            edid_hex = None
            try:
                with open(edid_file, "rb") as f:
                    edid_data = f.read()
                    edid_hex = edid_data.hex()
            except Exception as e:
                print_error(_("Error reading EDID from {}: {}").format(edid_file, e))

            monitor = {
                "connector": connector_name,
                "status": status,
                "edid_path": edid_file,
                "edid_hex": edid_hex
            }
            displays.append(monitor)

    return displays

def handle_interactive_mode(config):
    print_header(_("CONFIGURATION MODE"))
    print(_("\nStep 1: Disconnect all displays except the ones required to run Workbench."))
    print(_("        These remaining displays will be EXCLUDED from analysis.\n"))

    input(_(">> Press ENTER once you are ready... "))

    while True:
        excluded_monitors = {}
        excluded_disks = {}
        try:
            monitors = get_displays() or []
            disks = [ d for d in get_disks() if d.get("type") == "disk"]


            print_warning(_("\nDetected displays/disks to exclude:"))
            print("-" * 60)
            if monitors:
                print(_("Displays:"))
                for m in monitors:
                    print(f"    {m.get('connector')}")
            else:
                print(_("  (No displays detected)"))

            if disks:
                print(_("Disks:"))
                for d in disks:
                    name = d.get("name")
                    model = d.get("model", "")
                    disk_type = "HDD" if d.get("rota") else "SSD"
                    size = d.get("size", "")
                    print(f" {name}: {model} ({disk_type}) - {size}")
            else:
                print(_("  (No disks detected)"))
            print("-" * 60)

            if ask_user(_("Confirm exclusion of these displays/disks?"), default="y"):
                excluded_monitors = monitors
                excluded_disks = [d.get("name") for d in disks]
                break
            else:
                print_warning(_("\n Exclusion cancelled. Retrying...\n"))
                continue
        except Exception as e:
            print_error(_("Error while detecting devices: {} ").format(e))

    print_header(_("Initial configuration completed."))

    if excluded_monitors:
        print(_("\nExcluded Displays:"))
        for m in excluded_monitors:
            print(f"    {m.get('connector')}")
    else:
        print(_("\nNo displays excluded."))

    if excluded_disks:
        print(_("\nExcluded Disks:"))
        for d in excluded_disks:
            print(f"    {d}")
    else:
        print(_("\nNo disks excluded. \n"))

    while True:
        print_header(_("Connect the disks/displays you want to analyze."))
        try:
            if config.get("display_server", None):
                input(_("\n>> Press ENTER to scan for new displays or 'Ctrl + C' to exit..."))
                display_mode(config, excluded_monitors)
            else:
                input(_("\n>> Press ENTER to scan for new disks or 'Ctrl + C' to exit..."))
                disk_mode(config, excluded_disks)
        except (KeyboardInterrupt, EOFError):
            print_warning(_("\nExiting interactive mode..."))
            break


def disk_mode(config, excluded_disks):
    try:
        all_disks = get_disks() or []
        excluded_names = {d if isinstance(d, str) else d.get("name") for d in (excluded_disks or [])}
        # empty dict for local debug
        #excluded_names = {}

        candidates = []
        for d in all_disks:
            try:
                if d.get("type") != "disk":
                    continue
                if 'boot' in d.get('mountpoints', []):
                    continue
                if d.get("name") in excluded_names:
                    continue
                candidates.append(d)
            except Exception:
                continue

        if not candidates:
            print_warning(_("\n No additional disks found for analysis."))
            return

        print_header(_("Available disks for analysis"))

        # TABLE HEADER
        h_name = _("NAME")
        h_type = _("TYPE")
        h_size = _("SIZE")
        h_model = _("MODEL")

        print(f"{C_BOLD}{h_name:<10} {h_type:<8} {h_size:<10} {h_model}{C_END}")
        print("-" * 60)

        for d in candidates:
            name = d.get("name")
            model = d.get("model", _("N/A"))
            rota = d.get("rota")
            disk_type = "HDD" if rota else "SSD"
            size = d.get("size", "")

            color = C_YELLOW if rota else C_GREEN

            print(f"{color}{name:<10} {disk_type:<8} {size:<10} {model}{C_END}")
        print("=" * 60)

        if not ask_user(_("Do you want to create a snapshot of these disk(s)?")):
            print_warning(_("\nSkipping snapshot. Retrying...\n"))
            return

        snaps = []
        failed_disks = 0
        for disk in candidates:
            disk_name = disk.get("name")
            print_header(_("Creating snapshot for disk: {}").format(disk_name))

            if not os.path.exists(f"/dev/{disk_name}"):
                print_warning(_("Disk %s is no longer connected. Skipping.") % disk_name)
                failed_disks += 1
                continue

            snapshot_dict, snap_uuid = gen_disk_snapshot(disk, config)
            if not snapshot_dict or not snap_uuid:
                print_error(_("Failed to generate snapshot data for %s.") % disk_name)
                failed_disks += 1
                continue

            snapshot_json = save_snapshot_in_disk(snapshot_dict, snap_uuid, config)
            snaps.append((snapshot_json, snap_uuid))

        if failed_disks > 0:
            print_warning(_("  {} disks failed or were skipped.").format(failed_disks))

        for snapshot_json, snap_uuid in snaps:
            send_snapshot(snapshot_json, snap_uuid, config)

        print_success(_("\n All disk snapshots processed successfully.\n"))
        return

    except Exception as e:
        print_error(f"Error: {e}")


def display_mode(config, excluded_monitors):
    try:
        m = get_displays() or []
        excluded_hex = {hex.get("edid_hex") for hex in excluded_monitors}
        #empty list for local debug
        # excluded_hex = {}

        displays = [
            m for m in m if m.get("edid_hex") not in excluded_hex
        ]
        if not displays:
            print_warning(_("\n No additional displays found for analysis.\n"))
            return

        print_header(_("Available displays for analysis"))
        for d in displays:
            print(f"   {d.get('connector')}")
        print("=" * 60)

        if not ask_user(_("Do you want to create a snapshot of these display(s)?")):
            print_warning(_("\nSkipping snapshot. Retrying...\n"))
            return

        snaps = []
        for display in displays:
            print_header(_("Creating snapshot for display: {}").format(display.get('connector')))
            snapshot_dict, snap_uuid = gen_display_snapshot(display, config)
            snapshot_json = save_snapshot_in_disk(snapshot_dict, snap_uuid, config)
            snaps.append((snapshot_json, snap_uuid))

        for snapshot_json, snap_uuid in snaps:
            send_snapshot(snapshot_json, snap_uuid, config)


        print_success(_("\n All snapshots processed successfully.\n"))
        return

    except Exception as e:
        print_error(f"Error: {e}")


def main():
    prepare_lang()
    prepare_logger()

    logger.info(_("START"))

    # Parse the command-line arguments
    args = parse_args()

    # Load the config file, either specified via --config or the default 'settings.ini'
    config_file = args.config

    config = load_config(config_file)

    # TODO show warning if non root, means data is not complete
    #   if annotate as potentially invalid snapshot (pending the new API to be done)
    if os.geteuid() != 0:
        logger.warning(_("This script must be run as root. Collected data will be incomplete or unusable"))

    # --- Interactive Mode ---
    if config.get("display_server") or config.get("disk_server") :
        config["legacy"] = None
        handle_interactive_mode(config)
        logger.info(_("END"))
        return

    # --- Normal Mode ---
    snapshot_dict, snap_uuid = gen_device_snapshot(config)
    snap_json = save_snapshot_in_disk(snapshot_dict, snap_uuid, config)
    if not snap_json:
        logger.info(_("Error creating device Snapshot. Aborting"))

    send_snapshot(snap_json, snap_uuid, config)

    logger.info(_("END"))


if __name__ == '__main__':
    main()
