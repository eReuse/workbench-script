# -*- coding: utf-8 -*-

import os
import json
import uuid
import hashlib
import argparse
import configparser

import requests


from datetime import datetime


## Legacy Functions ##
def convert_to_legacy_snapshot(snapshot):
    snapshot["sid"] = str(uuid.uuid4()).split("-")[0]
    snapshot["software"] = "workbench-script"
    snapshot["version"] = "dev"
    snapshot["schema_api"] = "1.0.0"
    snapshot["settings_version"] = "No Settings Version (NaN)"
    snapshot["timestamp"] = snapshot["timestamp"].replace(" ", "T")
    snapshot["data"]["smart"] = snapshot["data"]["disks"]
    snapshot["data"].pop("disks")
    snapshot.pop("code")
    snapshot.pop("erase")
    
## End Legacy Functions ##


## Utility Functions ##
def logs(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as err:
            print(err)
            return ''

    return wrapper


@logs
def exec_cmd(cmd):
    return os.popen(cmd).read()

@logs
def exec_cmd_erase(cmd):
    print(cmd)
    return ''
    # return os.popen(cmd).read()


def gen_code():
    uid = str(uuid.uuid4()).encode('utf-8')
    return hashlib.shake_256(uid).hexdigest(3)

## End Utility functions ##


SNAPSHOT_BASE = {
    'timestamp': str(datetime.now()),
    'type': 'Snapshot',
    'uuid': str(uuid.uuid4()),
    'code': gen_code(),
    'software': "EreuseWorkbench",
    'version': "0.0.1",
    'data': {},
    'erase': []
}


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
    cmd = f'smartctl -x --json=cosviu /dev/{disk}'
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

    return data_list

## End Command Functions ##


# TODO permitir selección
# TODO permitir que vaya más rápido
def get_data(all_disks):
    lshw = 'sudo lshw -json'
    hwinfo = 'sudo hwinfo --reallyall'
    dmidecode = 'sudo dmidecode'
    data = {
        'lshw': json.loads(exec_cmd(lshw) or "{}"),
        'disks': smartctl(all_disks),
        'hwinfo': exec_cmd(hwinfo),
        'dmidecode': exec_cmd(dmidecode)
    }

    return data


def gen_snapshot(all_disks):
    snapshot = SNAPSHOT_BASE.copy()
    snapshot['data'] = get_data(all_disks)
    return snapshot


def save_snapshot_in_disk(snapshot, path):
    snapshot_path = os.path.join(path, 'snapshots')

    filename = "{}/{}_{}.json".format(
        snapshot_path,
        datetime.now().strftime("%Y%m%d-%H_%M_%S"),
        snapshot['uuid'])

    try:
        if not os.path.exists(snapshot_path):
            os.makedirs(snapshot_path)
            print(f"workbench: INFO: Created snapshots directory at '{snapshot_path}'")

        with open(filename, "w") as f:
            f.write(json.dumps(snapshot))
        print(f"workbench: INFO: Snapshot written in path '{filename}'")
    except Exception as e:
        try:
            print(f"workbench: WARNING: Attempting to save in actual path. Reason: Failed to write in snapshots directory:\n    {e}.")
            fallback_filename = "{}/{}_{}.json".format(
                path,
                datetime.now().strftime("%Y%m%d-%H_%M_%S"),
                snapshot['uuid'])
            with open(fallback_filename, "w") as f:
                f.write(json.dumps(snapshot))
                print(f"workbench: INFO: Snapshot written in fallback path '{fallback_filename}'")
        except Exception as e:
            print(f"workbench: ERROR: Could not save snapshot locally. Reason: Failed to write in fallback path:\n    {e}")

# TODO sanitize url, if url is like this, it fails
#   url = 'http://127.0.0.1:8000/api/snapshot/'
def send_snapshot_to_devicehub(snapshot, token, url):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(url, data=json.dumps(snapshot), headers=headers)
        if 200 <= response.status_code < 300:
            print(f"workbench: INFO: Snapshot successfully sent to '{url}'")
        else:
            txt = "workbench: ERROR: Failed to send snapshot. HTTP {}: {}".format(
                response.status_code,
                response.text
            )
            raise Exception(txt)

        try:
            res = json.loads(response.text)
            if res.get('public_url'):
                qr = "echo {} | qrencode -t ANSI".format(res['public_url'])
                print(exec_cmd(qr))
            if res.get("dhid"):
                print(res['dhid'])
        except Exception:
            print(response.text)

    except Exception as e:
        print(f"workbench: ERROR: Snapshot not remotely sent. URL '{url}' is unreachable. Do you have internet? Is your server up & running?\n    {e}")

def load_config(config_file="settings.ini"):
    """
    Tries to load configuration from a config file.
    """
    config = configparser.ConfigParser()

    if os.path.exists(config_file):
        # If config file exists, read from it

        print(f"workbench: INFO: Found config file in path: '{config_file}'.")
        config.read(config_file)
        path = config.get('settings', 'path', fallback=os.getcwd())
        # TODO validate that has http:// start
        url = config.get('settings', 'url', fallback=None)
        token = config.get('settings', 'token', fallback=None)
        # TODO validate that the device exists?
        device = config.get('settings', 'device', fallback=None)
        erase = config.get('settings', 'erase', fallback=None)
        legacy = config.get('settings', 'legacy', fallback=None)
    else:
        print(f"workbench: ERROR: Config file '{config_file}' not found. Using default values.")
        path = os.path.join(os.getcwd())
        url, token, device, erase, legacy = None, None, None, None, None

    return {
        'path': path,
        'url': url,
        'token': token,
        'device': device,
        'erase': erase,
        'legacy': legacy
    }

def parse_args():
    """
    Parse config argument, if available
    """
    parser = argparse.ArgumentParser(description="Optional config loader for workbench.")
    parser.add_argument(
        '--config',
        help="Path to the config file. Defaults to 'settings.ini' in the current directory.",
        default="settings.ini"  # Fallback to 'settings.ini' by default
    )
    return parser.parse_args()

def main():
    vline='\n___________\n\n'
    print(f"{vline}workbench: START\n")

    # Parse the command-line arguments
    args = parse_args()

    # Load the config file, either specified via --config or the default 'settings.ini'
    config_file = args.config

    config = load_config(config_file)

    # TODO show warning if non root, means data is not complete
    #   if annotate as potentially invalid snapshot (pending the new API to be done)
    if os.geteuid() != 0:
        print("workbench: WARNING: This script must be run as root. Collected data will be incomplete or unusable")

    all_disks = get_disks()
    snapshot = gen_snapshot(all_disks)

    if config['erase'] and config['device'] and not config.get("legacy"):
        snapshot['erase'] = gen_erase(all_disks, config['erase'], user_disk=config['device'])
    elif config['erase'] and not config.get("legacy"):
        snapshot['erase'] = gen_erase(all_disks, config['erase'])

    if config.get("legacy"):
        convert_to_legacy_snapshot(snapshot)
        
    save_snapshot_in_disk(snapshot, config['path'])

    if config['url']:
        send_snapshot_to_devicehub(snapshot, config['token'], config['url'])

    print(f"\nworkbench: END{vline}")


if __name__ == '__main__':
    main()
