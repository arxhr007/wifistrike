<p align="center" ><img src="" data-canonical-src="https://raw.githubusercontent.com/BLINKING-IDIOT/Aliens_eye/main/photos/logo.png" width="450" height="400" /></p>
<h1 align="center">Pure python wifi deauth</h1>
<h1 align="center">Doesn't use any aircrack-ng tools</h1>
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

## Requirements

Before you begin, ensure you have the following:

- Python 3.x
- `pip` (Python package installer)
- `psutil` and `scapy` Python libraries (automatically installed with `requirements.txt`)

## if they are not installed, install it by:
* for linux:
    - install git from [here](https://linuxhint.com/install-use-git-linux/) 
    - install python3 from [here](https://www.python.org/downloads/) 
    - [click here](https://www.tecmint.com/install-pip-in-linux/) for installing pip 

# Installation in Linux:
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
***It need root privilege to  manipulate network interfaces, perform packet sniffing and injection, and execute system commands***
<br>
**To auto detect network interfaces and show the attack options**
```shell script
sudo wifistrike
```
**To manually select network interface**
```shell script
sudo wifistrike -i <interface_name>
```
**To set gateway manually**
```shell script
sudo wifistrike -g <gateway_mac>
```
**To set target manually**
```shell script
sudo wifistrike -t <target_mac> // (use `-t 0` for deauth all)
```

**you can use multiple flags and if one is missing it will compensate it**
```shell script
sudo wifistrike -i <network_interface> -g <gateway_mac> -t <target_mac>
```
**In case any error you need to change network interface to manage or moniter mode**
```shell script
sudo wifistrike -man <network_interface> // to manage mode
sudo wifistrike -mon <network_interface> // to moniter mode

```

**for reconnaissance**
```shell script
sudo wifistrike -l // to get the network interfaces
sudo wifistrike -sw // to get the wifi available
sudo wifistrike -st // to get the target available also can define gateway(optinal) -g <gateway_name>
```

## Enjoy!
<p><img aling="center"src=""/></p>
