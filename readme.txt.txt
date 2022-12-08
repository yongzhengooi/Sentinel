INSTALLATION GUIDE
=================================
1. install the python
2. install the wireshark using the exe provided or https://www.wireshark.org/download.html
3. Reboot the system (if wireshark required)
3. click on install in the folder
4. start the application -double click on SENTINEL

App manual
==================================
Dashboard
---------
(This page show the dashboard of application)
Top right- Current live packet
Top left- Percentage of benign and malicious capture using the system
Bottom right- Type of attack detected
Bottom left- Current attack event on the system

Event
---------
(This page could use to evaluate the event)
To filter the event- Select attribute and key in the input
To edit the event- double click on location you want to edit then key in the new value and press enter

Rule
--------
(This page create and search for custom rule)
To create custom rule - fill in valid IP in src IP and dst IP
			    - fill in the port between 0-65535 or any
				(any) is the rule from 0 to 65535
To filter the rule- Select attribute and key in the input
To edit the rule- double click on location you want to edit then key in the new value and press enter

Setting
--------
(This page use to control application behaviour)
Detection level - To set the threshold to raise the error ( the attacks detected below the threshold will not be show)
Detection range- Set the range to capture the entire network or the host only
Add email - add the email for the system to send the alert email when attacks is detected
Machine learning algorithm - Let user to decide which algorithm suited them better
Retrain all data model - resetup the model for ML analysis in case the data is missing or corrupted
Startup on boot: start the application when the system is boot

Export
---------
To export file- select the files to export, select the export location (if the location is not specific ,the default location will be saved at "exported" folder)

Switching ON/OFF
-----------------
start the system - click on the switch on left side navigation bar

