#!/usr/bin/env python3

import subprocess
import re

def get_monitors():
    try:
        #https://docs.python.org/3/library/subprocess.html
        result = subprocess.run(
            ["inxi", "-Gxx", "--edid"],
            capture_output=True,
            text=True,
            check=True
        )

        monitors = []

        for line in result.stdout.split('\n'):
            if "Monitor" in line:
                monitors.append(line)
        return monitors

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error: {e}")
        return []

def select_monitor(monitors):
    if not monitors:
        print("No monitors found.")
        return None

    print("\nDetected monitors:")
    for i, monitor in enumerate(monitors, 1):
        print(f"{i}. {monitor}")

    while True:
        try:
            choice = int(input("\nSelect one monitor (1-{}): ".format(len(monitors))))
            if 1 <= choice <= len(monitors):
                return monitors[choice-1]
            print("Please enter a valid number.")
        except ValueError:
            print("Please enter a number.")

def main():
    monitors = get_monitors()
    if monitors:
        selected = select_monitor(monitors)
        if selected:
            print(f"\nSelected monitor: {selected}")
    else:
        print("Could not retrieve display information.")

if __name__ == "__main__":
    main()
