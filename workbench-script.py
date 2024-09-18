# -*- coding: utf-8 -*-

import os
import json
import uuid
import hashlib
import argparse

import ntplib
import requests


from datetime import datetime


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
        return exec_smart(disk)

    data_list = []
    for disk in all_disks:
        if disk['type'] == 'disk':
            data = exec_smart(disk['name'])
            data_list.append(data)

    return data_list

## End Command Functions ##


def get_data(all_disks):
    lshw = 'lshw -json'
    hwinfo = 'hwinfo --reallyall'
    dmidecode = 'dmidecode'
    data = {
        'lshw': exec_cmd(lshw),
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
    filename = "{}/{}_{}.json".format(
        path,
        datetime.now().strftime("%Y%m%d-%H_%M_%S"),
        snapshot['uuid']
    )
    with open(filename, "w") as f:
        f.write(json.dumps(snapshot))


def send_snapshot_to_devicehub(snapshot, token, url):
    headers = {
        f"Authorization": "Basic {token}",
        "Content-Type": "application/json"
    }
    return requests.post(url, data=snapshot, header=headers)


@logs
def sync_time():
    # is neccessary?
    ntplib.NTPClient()
    response = client.request('pool.ntp.org')


def main():
    print("START")
    parser=argparse.ArgumentParser()
    parser.add_argument("-p", "--path", required=True)
    parser.add_argument("-u", "--url", required=False)
    parser.add_argument("-t", "--token", required=False)
    parser.add_argument("-d", "--device", required=False)
    parser.add_argument(
        "-e",
        "--erase",
        choices=["basic", "baseline", "enhanced"],
        required=False
    )
    args=parser.parse_args()

    if args.device and not args.erase:
        print("error: argument --erase: expected one argument")
        return
    
    if args.token and not args.url:
        print("error: argument --url: expected one argument")
        return
    
    if args.url and not args.token:
        print("error: argument --token: expected one argument")
        return

    all_disks = get_disks()
    snapshot = gen_snapshot(all_disks)

    if args.erase and args.device:
        snapshot['erase'] = gen_erase(all_disks, args.erase, user_disk=args.device)
    elif args.erase:
        snapshot['erase'] = gen_erase(all_disks, args.erase)

    save_snapshot_in_disk(snapshot, args.path)
    
    if args.url:
        send_snapshot_to_devicehub(snapshot, args.token, args.url)

    print("END")


if __name__ == '__main__':
    main()
