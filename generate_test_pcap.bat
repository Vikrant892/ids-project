@echo off
echo Generating synthetic test PCAP...
call venv\Scripts\activate.bat
set PYTHONPATH=%CD%
python scripts\generate_pcap.py
echo Done. File saved to data\pcap\test.pcap
pause
