# -*- coding: utf-8 -*-

import os
import json
import uuid
import hashlib
import argparse
import configparser
import urllib.request

import gettext
import locale
import logging

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

@logs
def get_disks():
    disks = json.loads(
        exec_cmd('lsblk -Jdo NAME,TYPE,MOUNTPOINTS,ROTA,TRAN')
    )
    return disks.get('blockdevices', [])


@logs
def gen_erase(type_erase, user_disk=None):
    if user_disk:
        return exec_cmd(f"sanitize -d {user_disk} -m {type_erase}")
    return exec_cmd(f"sanitize -a -m {type_erase}")
    # return exec_cmd(f"sanitize -a -m {type_erase} --confirm")


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

    return data_list

## End Command Functions ##


# TODO permitir selección
# TODO permitir que vaya más rápido
def get_data(all_disks):
    lshw = 'sudo lshw -json'
    hwinfo = 'sudo hwinfo --reallyall'
    dmidecode = 'sudo dmidecode'
    lspci = 'sudo lspci -vv'
    data = {
        'lshw': exec_cmd(lshw) or "{}",
        'disks': smartctl(all_disks),
        'hwinfo': exec_cmd(hwinfo),
        'dmidecode': exec_cmd(dmidecode),
        'lspci': exec_cmd(lspci)
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
            logger.info(_("Created snapshots directory at '%s'"), snapshot_path)
        with open(filename, "w") as f:
            f.write(json.dumps(snapshot))
        logger.info(_("Snapshot written in path '%s'"), filename)
    except Exception as e:
        try:
            logger.warning(_("Attempting to save file in actual path. Reason: Failed to write in snapshots directory:\n    %s."), e)
            fallback_filename = "{}/{}_{}.json".format(
                path,
                datetime.now().strftime("%Y%m%d-%H_%M_%S"),
                snapshot['uuid'])
            with open(fallback_filename, "w") as f:
                f.write(json.dumps(snapshot))
                logger.warning(_("Snapshot written in fallback path '%s'"), fallback_filename)
        except Exception as e:
            logger.error(_("Could not save snapshot locally. Reason: Failed to write in fallback path:\n    %s"), e)

# TODO sanitize url, if url is like this, it fails
#   url = 'http://127.0.0.1:8000/api/snapshot/'
def send_snapshot_to_devicehub(snapshot, token, url):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        data = json.dumps(snapshot).encode('utf-8')
        request = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(request) as response:
            status_code = response.getcode()
            response_text = response.read().decode('utf-8')

        if 200 <= status_code < 300:
            logger.info(_("Snapshot successfully sent to '%s'"), url)

        try:
            response = json.loads(response_text)
            if response.get('url'):
                # apt install qrencode
                qr = "echo {} | qrencode -t ANSI".format(response['url'])
                print(exec_cmd(qr))
                print("url: {}".format(response['url']))
            if response.get("dhid"):
                print("dhid: {}".format(response['dhid']))
        except Exception:
            logger.error(response_text)

    except Exception as e:
        logger.error(_("Snapshot not remotely sent to URL '%s'. Do you have internet? Is your server up & running? Is the url token authorized?\n    %s"), url, e)

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
    else:
        logger.error(_("Config file '%s' not found. Using default values."), config_file)
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

    # TODO show warning if non root, means data is not complete
    #   if annotate as potentially invalid snapshot (pending the new API to be done)
    if os.geteuid() != 0:
        logger.warning(_("This script must be run as root. Collected data will be incomplete or unusable"))

    all_disks = get_disks()
    snapshot = gen_snapshot(all_disks)

    if config.get("legacy"):
        convert_to_legacy_snapshot(snapshot)
    else:
        snapshot['erase'] = gen_erase(config['erase'], user_disk=config['device'])

    save_snapshot_in_disk(snapshot, config['path'])

    if config['url']:
        send_snapshot_to_devicehub(snapshot, config['token'], config['url'])

    logger.info(_("END"))


if __name__ == '__main__':
    main()
