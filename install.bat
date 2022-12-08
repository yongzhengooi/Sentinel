@echo off
pip install -r requirements.txt -v
pip install torch torchvision torchaudio --extra-index-url https://download.pytorch.org/whl/cu116
cd cicflowmeter-main
python setup.py install
pause
