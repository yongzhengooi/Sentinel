@echo off
echo "Initializing the SENTINEL IDS SYSTEM..."
start /B python IDS.py
echo "Activating machine Learning assist tool..."
cd data
for /f "skip=1" %%x in ('wmic os get localdatetime') do if not defined MyDate set MyDate=%%x
for /f %%x in ('wmic path win32_localtime get /format:list ^| findstr "="') do set %%x
set fmonth=00%Month%
set fday=00%Day%
set today=%Year%-%fmonth:~-2%-%fday:~-2%
set fileformat=.csv
set header=cic_
set concat=%header%%today%%fileformat%
echo %concat%
cicflowmeter -i Wi-Fi -c %concat%
pause