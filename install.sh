#!/bin/bash
clear
echo
echo

if [[ $(id -u) -ne 0 ]] ; then
    echo "You need root access to install the program."
    echo "Please enter the password to login as root!"
    sudo bash ${0}
    exit
fi

echo "NOTE: You also need to install necessary packages from requirements.txt"

for i in 3 2 1
do
    echo "Starting installation process in ${i}";
    sleep 1
done

echo

if [ -f /usr/bin/wifistrike ]; then
    rm /usr/bin/wifistrike &>/dev/null
fi

cp wifistrike.py /usr/bin/wifistrike
if [[ $? -ne 0 ]]; then
    echo "Failed to copy wifistrike.py to /usr/bin/"
    exit 1
fi

chmod +x /usr/bin/wifistrike
if [[ $? -ne 0 ]]; then
    echo "Failed to make /usr/bin/wifistrike executable."
    exit 1
fi

if ! command -v pip &> /dev/null; then
    echo "pip is not installed. Please install pip first."
    exit 1
fi

pip install -r requirements.txt --break-system-packages
if [[ $? -ne 0 ]]; then
    echo "Failed to install the required packages."
    exit 1
fi

echo "Installed successfully!"
echo "Run using : sudo wifistrike"

