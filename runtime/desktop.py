"""Non-root X11 desktop session. No network privileges or system installation."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--command', required=True)
p.add_argument('--state', required=True)
a = p.parse_args()
state = Path(a.state)
running = True
def stop(*_):
    global running
    running = False
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
window_manager = subprocess.Popen(['openbox', '--sm-disable'])
command = json.loads(a.command)
child = None
try:
    while running:
        child = subprocess.Popen(command)
        (state / 'gui.pid').write_text(str(child.pid))
        while running and child.poll() is None:
            time.sleep(.5)
        if running:
            time.sleep(3)
finally:
    if child and child.poll() is None:
        child.terminate()
        try:child.wait(timeout=10)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
    window_manager.terminate()
    try:window_manager.wait(timeout=5)
    except subprocess.TimeoutExpired:window_manager.kill();window_manager.wait(timeout=3)
