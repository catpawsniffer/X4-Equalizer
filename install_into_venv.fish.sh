#!/usr/bin/fish

python -m venv venv
source venv/bin/activate.fish     
python -m pip install -r requirements.txt
python x4-equalizer.py