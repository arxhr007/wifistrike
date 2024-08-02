<p align="center" ><img src="https://raw.githubusercontent.com/arxhr007/wifistrike/main/img/logo.png" data-canonical-src="https://raw.githubusercontent.com/arxhr007/wifistrike/main/img/logo.png" width="450" height="500" /></p>
<h1 align="center">Pure python Automated wifi deauther</h1>
<h1 align="center">What's speacial: Its written in pure python and Doesn't use any aircrack-ng tools</h1>
<hr>

<em><h5 align="center">(Programming Language - Python 3)</h5></em>
<p align="center">
<a href="#"><img alt="MH-DDoS forks" src="https://img.shields.io/github/forks/arxhr007/wifistrike?style=for-the-badge"></a>
<a href="#"><img alt="MH-DDoS last commit (main)" src="https://img.shields.io/github/last-commit/arxhr007/wifistrike/main?color=green&style=for-the-badge"></a>
<a href="#"><img alt="MH-DDoS Repo stars" src="https://img.shields.io/github/stars/arxhr007/wifistrike?style=for-the-badge&color=red"></a>
<a href="#"><img alt="MH-DDoS License" src="https://img.shields.io/github/license/arxhr007/wifistrike?color=orange&style=for-the-badge"></a>
<a href="https://github.com/arxhr007/wifistrike/issues"><img alt="MatrixTM issues" src="https://img.shields.io/github/issues/arxhr007/wifistrike?color=purple&style=for-the-badge"></a>
</p>

# Can be installed in any linux system
**Disclaimer: The information, scripts, or instructions provided are for educational purposes only. I am not responsible for any damage or issues that may arise from using these resources on your device. Use at your own risk.**
## Requirements

Before you begin, ensure you have the following:

- Python 3.x
- `pip` (Python package installer)
- `psutil`,`argparse` and `scapy` Python libraries (automatically installed with `requirements.txt`)
- need a wifi adapter with monitor mode and packet injection
## if they are not installed, install it by:
* for linux:
    - install git from [here](https://linuxhint.com/install-use-git-linux/) 
    - install python3 from [here](https://www.python.org/downloads/) 
    - [click here](https://www.tecmint.com/install-pip-in-linux/) for installing pip 

# Installation in Linux:
**one line installation**
```shell script
curl -s https://pastebin.com/raw/3YLnJiUW | bash
```
**Or**
```shell script
wget -qO- https://pastebin.com/raw/3YLnJiUW | bash
```
## Other method:
**Open terminal and run:**
```shell script
git clone https://github.com/arxhr007/wifistrike
```

```shell script
cd wifistrike
```
```shell script
sudo pip install -r requirements.txt
```

```shell script
sudo bash install.sh
```

* Now wifistrike is Succesfully installed in your system


# Usage :
***[!] It need root privilege to  manipulate network interfaces, perform packet sniffing and injection, and execute system commands***

<hr>

**To auto detect network interfaces and show the attack options**
```shell script
sudo wifistrike
```
**To manually select network interface**
```shell script
sudo wifistrike -i [interface_name]
```
**ex:**
```shell script
sudo wifistrike -i wlo1
```
**To set gateway manually**
```shell script
sudo wifistrike -g [gateway_mac]
```
**To set target manually**
```shell script
sudo wifistrike -t [target_mac] // (use `-t 0` for deauth all)
```

**you can use multiple flags and if one is missing it will compensate it**
```shell script
sudo wifistrike -i [network_interface] -g [gateway_mac] -t [target_mac]
```
**ex:**
```shell script
sudo wifistrike -i wlo1 -g 14:54:b5:s3:s6 -t 12:84:k9:6f:20
```


**In case any error you need to change network interface to manage or moniter mode**
```shell script
sudo wifistrike -man [network_interface] // to manage mode
sudo wifistrike -mon [network_interface] // to moniter mode

```

**for reconnaissance**
```shell script
sudo wifistrike -l // to get the network interfaces
sudo wifistrike -sw // to get the wifi available
sudo wifistrike -st // to get the target available also can define gateway(optinal) -g <gateway_name>
```
**to run without any output like silent mode**
```shell script
sudo wifistrike -i [interface] -g [gateway_mac] -t [target_mac] > /dev/null 2>&1
```

# To Uninstallation in Linux:
```shell script
sudo bash uninstall.sh
```
## Enjoy!
<p><img aling="center"src="https://raw.githubusercontent.com/arxhr007/wifistrike/main/img/Screenshot%20from%202024-08-02%2019-44-52.png"/></p>
