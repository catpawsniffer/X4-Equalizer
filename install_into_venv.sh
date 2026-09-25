#!/usr/bin/sh

python -m venv venv
source venv/bin/activate     
python -m pip install -r requirements.txt
python x4-equalizer.py