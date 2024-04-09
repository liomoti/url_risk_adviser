#!/bin/bash

# Check if pip3 is installed
if command -v pip3 &>/dev/null; then
    # Install required packages
    pip3 install -r requirements.txt
    # Execute Python script
    python3 "url_risk_adviser.py"
else
    echo "Error: pip3 not detected!"
    echo "Please make sure you have pip3 and Python installed and try again."
fi

# Prompt the user to press Enter before exiting
read -p "Press Enter to continue..."
