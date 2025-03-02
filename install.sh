#!/bin/bash
clear
echo 
echo
if [[ $(id -u) -ne 0 ]] ; then
	printf "you need root assess to install the program\n\n"

	printf  "so please enter the password to login as root!\n\n"

	sudo bash ${0}
	printf "\n\n"
	exit
fi
printf "NOTE: you also need install necessary packages in requirements.txt\n"
for i in 3 2 1
do
	echo "staring installation process in ${i}" ; 
	sleep 1
done
printf "\n\n" 
rm /usr/bin/wifistrike &>/dev/null
cp wifistrike.py /usr/bin/wifistrike
chmod +x /usr/bin/wifistrike
pip install -r requirements.txt
printf "\n\ninstalled successfully!"
