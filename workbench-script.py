# -*- coding: utf-8 -*-

# Copyright (c) 2024 pangea.org Associació Pangea - Coordinadora Comunicació per a la Cooperació
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
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


SNAPSHOT_BASE = {
    'timestamp': str(datetime.now()),
    'type': 'Snapshot',
    'uuid': str(uuid.uuid4()),
    'software': "workbench-script",
    'version': "0.0.1",
    'operator_id': "",
    'data': {},
    'erase': []
}


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
        exec_cmd('lsblk -Jdo NAME,TYPE,MOUNTPOINTS,ROTA,TRAN')
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
def get_data(all_disks):
    dmidecode = 'sudo dmidecode'
    inxi = "sudo inxi -afmnGEMABD -x 3 --edid --output json --output-file print"

    data = {
        'smartctl': smartctl(all_disks),
        'dmidecode': exec_cmd(dmidecode),
        'inxi': exec_cmd(inxi)
    }

    return data


def gen_snapshot(all_disks):
    snapshot = SNAPSHOT_BASE.copy()
    snapshot['data'] = get_data(all_disks)
    return snapshot


def save_snapshot_in_disk(snapshot, path, snap_uuid):
    snapshot_path = os.path.join(path, 'snapshots')

    filename = "{}/{}_{}.json".format(
        snapshot_path,
        datetime.now().strftime("%F_%H-%M-%S"),
        snap_uuid)

    try:
        if not os.path.exists(snapshot_path):
            os.makedirs(snapshot_path)
            logger.info(_("Created snapshots directory at '%s'"), snapshot_path)
        with open(filename, "w") as f:
            f.write(snapshot)
        logger.info(_("Snapshot written in path '%s'"), filename)
    except Exception as e:
        try:
            logger.warning(_("Attempting to save file in actual path. Reason: Failed to write in snapshots directory:\n    %s."), e)
            fallback_filename = "{}/{}_{}.json".format(
                path,
                datetime.now().strftime("%Y%m%d-%H_%M_%S"),
                snap_uuid)
            with open(fallback_filename, "w") as f:
                f.write(snapshot)
                logger.warning(_("Snapshot written in fallback path '%s'"), fallback_filename)
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
            "data": snapshot
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
            return json.dumps(snapshot)
        else:
            logger.error(_("Failed to sign credential. URL: '%s'"), url)
            return json.dumps(snapshot)

    except Exception as e:
        logger.error(_("Credential not remotely signed by IdHub URL '%s'. Do you have internet? Is your server up & running? Is the url token authorized?\n    %s"), url, e)
        return json.dumps(snapshot)

# apt install qrencode
def generate_qr_code(url, disable_qr):
    """Generate and print QR code for the given URL."""
    if disable_qr:
        return
    qr_command = "echo {} | qrencode -t ANSI".format(url)
    print(exec_cmd(qr_command))

# TODO sanitize url, if url is like this, it fails
#   url = 'http://127.0.0.1:8000/api/snapshot/'
def send_snapshot_to_devicehub(snapshot, token, url, ev_uuid, legacy, disable_qr, http_max_retries=5, http_retry_delay=5):
    """Send snapshot to be stored in devicehub inventory service"""
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
            data = snapshot.encode('utf-8')
            status_code, response_text = http_post(url, data, headers)

            if 200 <= status_code < 300:
                logger.info(_("Snapshot successfully sent to '%s'"), url)
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


def load_config(config_file="settings.ini"):
    """
    Tries to load configuration from a config file.
    """
    # Define all keys and their default values in one place
    defaults = {
        'path': os.getcwd(),
        'url': None,
        'token': None,
        'device': None,
        'erase': None,
        'legacy': None,
        'url_wallet': None,
        'wb_sign_token': None,
        'disable_qr': None,
        'http_max_retries': 5,
        'http_retry_delay': 5
    }

    if not os.path.exists(config_file):
        logger.error(_("Config file '%s' not found. Using default values."), config_file)
        return defaults

    logger.info(_("Found config file in path: %s."), config_file)

    config = configparser.ConfigParser()
    config.read(config_file)

    result = {}

    # Iterate through defaults to extract values dynamically
    for key, default_val in defaults.items():
        if config.has_option('settings', key):
            # Auto-cast to int if the default value is an integer
            if isinstance(default_val, int):
                result[key] = config.getint('settings', key)
            else:
                result[key] = config.get('settings', key)
        else:
            result[key] = default_val

    # Validate URL
    if result.get('url') and not result['url'].startswith(('http://', 'https://')):
        logger.error(_("Configured URL does not start with http:// or https://"))
        exit(1)

    return result

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

def main():
    prepare_lang()
    prepare_logger()

    logger.info(_("START"))

    # Parse the command-line arguments
    args = parse_args()

    # Load the config file, either specified via --config or the default 'settings.ini'
    config_file = args.config

    config = load_config(config_file)
    legacy = config.get("legacy")

    # TODO show warning if non root, means data is not complete
    #   if annotate as potentially invalid snapshot (pending the new API to be done)
    if os.geteuid() != 0:
        logger.warning(_("This script must be run as root. Collected data will be incomplete or unusable"))

    all_disks = get_disks()
    snapshot = gen_snapshot(all_disks)
    snap_uuid = snapshot["uuid"]

    if config['erase'] and config['device'] and not legacy:
        snapshot['erase'] = gen_erase(all_disks, config['erase'], user_disk=config['device'])
    elif config['erase'] and not legacy:
        snapshot['erase'] = gen_erase(all_disks, config['erase'])

    token = config.get("token")
    if token:
        snapshot["token_hash"] = hashlib.sha3_256(token.encode("utf8")).hexdigest()

    if legacy:
        convert_to_legacy_snapshot(snapshot)
        snapshot = json.dumps(snapshot)
    else:
        url_wallet = config.get("url_wallet")
        wb_sign_token = config.get("wb_sign_token")

        if wb_sign_token:
            tk = wb_sign_token.encode("utf8")
            snapshot["operator_id"] = hashlib.sha3_256(tk).hexdigest()

        if url_wallet and wb_sign_token:
            snapshot = send_snapshot_to_idhub(snapshot, wb_sign_token, url_wallet)
        else:
            snapshot = json.dumps(snapshot)

    save_snapshot_in_disk(snapshot, config['path'], snap_uuid)

    if config['url']:
        send_snapshot_to_devicehub(
            snapshot,
            config['token'],
            config['url'],
            snap_uuid,
            legacy,
            config['disable_qr'],
            config['http_max_retries'],
            config['http_retry_delay']
        )

    logger.info(_("END"))


if __name__ == '__main__':
    main()
