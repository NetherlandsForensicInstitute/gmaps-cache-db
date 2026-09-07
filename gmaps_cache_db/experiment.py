import re
import subprocess
import time

import pandas as pd

# Automate experiment steps
# - Get starting timestamp
# - Start location gathering loop
# - Start screenrecording
# - Manually set up location input
# - Manually prime google maps navigation and start it
# - Manually start route

# Stop recording

MAPS_PKG = "com.google.android.apps.maps"
DUMPSYS_PATTERN = r"\[gps (?P<lat>\-?\d+\.\d+),(?P<lon>\-?\d+\.\d+).*et=(?P<timestamp>.*?) "

MAP_CACHE_PATH = "/data/media/0/Android/data/com.google.android.apps.maps/cache/diskcache/map_cache.db"
MAP_CACHE_KEY_PATH = "/data/user/0/com.google.android.apps.maps/app_/testdata/map_cache.key"

RECORDING_PATH = "/data/local/tmp/experiment_video.mp4"


def get_position():
    # cmd = 'adb shell dumpsys location | grep -oP "(?<=\[gps )(\d+\.\d+),(\d+\.\d+)"'
    cmd = "adb shell dumpsys location"
    dumpsys_output = subprocess.getoutput(cmd)
    hits = re.finditer(DUMPSYS_PATTERN, dumpsys_output)
    hit = next(hits)
    position = {k: hit.group(k) for k in ("timestamp", "lat", "lon")}
    position["timestamp"] = pd.to_timedelta(position["timestamp"])
    position["lat"] = float(position["lat"])
    position["lon"] = float(position["lon"])
    return position


def gather_locations(duration: int):
    t_start = time.time()
    print("Recording locations, press ctrl-c to stop")
    while (time.time() - t_start) < duration or duration < 0:
        try:
            yield get_position()
            time.sleep(1)
        except KeyboardInterrupt:
            break


def stop_app(app_package: str):
    ret = subprocess.run(f"adb shell am force-stop {app_package}".split())
    return ret.returncode


def start_app(app_package: str):
    ret = subprocess.run(f"adb shell am start {app_package}".split())
    return ret.returncode


def start_recording(filename):
    p = subprocess.Popen(f"adb shell screenrecord --time-limit 0 --bit-rate 1M {filename}".split())
    return p


def get_timestamps():
    uptime = subprocess.getoutput('adb shell "date -u && cat /proc/uptime"')
    timestamp, since_boot = uptime.split("\n")
    timestamp = pd.to_datetime(timestamp)
    since_boot = pd.Timedelta(seconds=float(since_boot.split(" ")[0]))
    return timestamp, since_boot


def remove_cache():
    for path in (MAP_CACHE_KEY_PATH, MAP_CACHE_PATH, MAP_CACHE_PATH + "-wal"):
        ret = subprocess.run(f"adb shell rm {path}".split())
        if ret.returncode:
            pass
            # raise ValueError('Could not remove cache!')


def pull_file(target_file: str, destination_path: str):
    ret = subprocess.run(f"adb pull {target_file} {destination_path}".split())
    if ret.returncode:
        raise ValueError(f"Could not pull {target_file}!")


def pull_cache(dest_path="/tmp"):
    for path in (MAP_CACHE_KEY_PATH, MAP_CACHE_PATH, MAP_CACHE_PATH + "-wal"):
        pull_file(path, dest_path)


def record_experiment(restart_app=None) -> pd.DataFrame:
    timestamp, since_boot = get_timestamps()

    if restart_app:
        stop_app(restart_app)
        time.sleep(0.5)
        remove_cache()
        start_app(restart_app)
    recording_process = start_recording(RECORDING_PATH)
    positions = pd.DataFrame(gather_locations(-1))
    recording_process.kill()

    positions["timestamp"] += timestamp - since_boot
    pull_cache()
    time.sleep(0.5)
    pull_file(RECORDING_PATH, "/tmp")
    return positions


if __name__ == "__main__":
    locations = record_experiment(restart_app=MAPS_PKG)
    locations.to_csv("/tmp/experiment_locations.csv")
    print(locations)
