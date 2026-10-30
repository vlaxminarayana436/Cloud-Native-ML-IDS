"""Harmless HTTP requests to the isolated demonstration target."""
import time
import urllib.error
import urllib.request

while True:
    try:
        with urllib.request.urlopen('http://lab-target:8080/', timeout=3) as response:
            print(f'lab target status: {response.status}', flush=True)
    except (OSError, urllib.error.URLError) as exc:
        print(f'lab target unavailable: {exc}', flush=True)
    time.sleep(3)
