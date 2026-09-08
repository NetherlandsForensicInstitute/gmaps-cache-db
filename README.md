# Google's map cache database
This repository contains a writeup of research done on forensic artefacts found in the `map_cache.db` database found in apps using Google's Maps SDK.
The writeup is submitted for publication on [https://dfir.pubpub.org/](https://dfir.pubpub.org/) and can be found in [dfir_review](./dfir_review/main.md).

Accompanying the writeup is some code that can be used to reproduce results and perform your own experiments and analyses.
The code can be found under [src](./src/).

# Usage
This project uses [pdm](https://pdm-project.org/en/latest/) as a dependency manager. For installation of PDM, please consult the
[PDM project website](https://pdm-project.org/en/latest/#installation).

Having PDM installed, install all dependencies of the project, run the following command to install the project
dependencies used in local development.

```commandline
pdm sync
```

Decrypt a map_cache database:
```commandline
pdm run decrypt <KEY_PATH> <DB_PATH> <OUT_PATH.geojson>
```


## Experimentation
Record your own (short) experiment for later analysis and visualization using adb access to a rooted device (an AVD is recommended).
This will delete the existing `map_cache.db` for ease and clarity.
A screen recording of the device will start, and the device location will be polled periodically.
You can then manually perform actions on the device to produce traces:

- Pan and zoom the map
- Replay a GPS route 

```commandline
pdm run experiment
# Press ctrl-c to stop, defaults to saving in /tmp
# Decrypt the pulled map_cache
pdm run decrypt /tmp/map_cache.key /tmp/map_cache.db /tmp/experiment.geojson
```

Visualize your experiment side by side with the tiles using example cells in [visualize.ipynb](./visualize.ipynb).

