# Google's map cache database
This repository contains a writeup of research done on forensic artefacts found in the `map_cache.db` database found in apps using Google's Maps SDK.
The writeup is submitted for publication on [https://dfir.pubpub.org/](https://dfir.pubpub.org/) and can be found in [dfir_review](./dfir_review/main.md).

Accompanying the writeup is some code that can be used to reproduce results and perform your own experiments and analyses.
The code can be found under [gmaps_cache_db](./gmaps_cache_db/).

# Usage
Install the project and dependencies: `pip install .`

Decrypt a map_cache database:
```commandline
python -m gmaps_cache_db.decrypt_map_cache <KEY_PATH> <DB_PATH> <OUT_PATH.geojson>
```


## Experimentation
Record your own (short) experiment for later analysis and visualization using adb access to a rooted device (an AVD is recommended).
This will delete the existing `map_cache.db` for ease and clarity.
A screen recording of the device will start, and the device location will be polled periodically.
You can then manually perform actions on the device to produce traces:

- Pan and zoom the map
- Replay a GPS route 

```commandline
python -m gmaps_cache_db.experiment
# Press ctrl-c to stop, defaults to saving in /tmp
# Decrypt the pulled map_cache
python -m gmaps_cache_db.decrypt_map_cache /tmp/map_cache.key /tmp/map_cache.db /tmp/experiment.geojson
```

Visualize your experiment side by side with the tiles using example cells in [visualize.ipynb](./visualize.ipynb).

