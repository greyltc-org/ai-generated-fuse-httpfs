#!/usr/bin/env bash

python -m venv --without-pip --system-site-packages --clear venv
source venv/bin/activate

python -m pip install -r requirements.txt