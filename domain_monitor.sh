#!/bin/bash

#TODO: enter path to folder
BASE=

source ${BASE}/.venv/bin/activate
python3 ${BASE}/src/domain_watcher.py "$@"