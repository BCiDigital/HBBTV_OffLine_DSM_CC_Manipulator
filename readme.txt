README - alterStream.py

This program takes an input transport stream file, gives the user the option of adding an AIT / replacing all SCTE35 packets with DSM-CC packets / both and then returns an output transport stream file with the same name as the input file but with added "_processed_YYYYMoDDHHMMSS"

The options will be presented to the user through the steps, to choose between options the integer keys are used, to input data all keys used.

HOW TO RUN

Ensure first that TSDuck is installed and up to date.

Run alterStream.py from command line:
python alterStream.py [param1]
[param1] - (String) file name for the transport stream (with or without extension)