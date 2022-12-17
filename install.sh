#!/bin/bash

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "This script needs to be run with root"
    exit
fi

unsatisfied=()
if [[ -f /usr/bin/python3 ]]; then
    echo "Found Python3"
else
    unsatisfied+=(python3)
fi
if [[ -f /usr/bin/pip3 ]]; then
    echo "Found python3-pip"
else   
    unsatisfied+=(python3-pip)
fi
if [[ -f /usr/bin/dnsmasq ]]; then
    echo "Found dnsmasq"
else
    unsatisfied+=(dnsmasq)
fi

if (( ${#unsatisfied[*]} == 0 )); then
    echo "All dependencies are present"
else    
    echo "The following dependencies are not present: ${unsatisfied[*]}"
    echo "Attempting to install them"
    if [[ -f /usr/bin/apt ]]; then
        echo "Installing with apt"
        apt --yes install ${unsatisfied[*]} &> /dev/null
        flag=$?
    elif [[ -f /usr/bin/yum ]]; then
        echo "Installing with yum"
        yum --assumeyes install ${unsatisfied[*]} &> /dev/null
        flag=$?
    elif [[ -f /usr/bin/dnf ]]; then
        echo "Installing with dnf"
        dnf --assumeyes install ${unsatisfied[*]} &> /dev/null
        flag=$?
    elif [[ -f /usr/bin/pacman ]]; then
        echo "Installing with pacman"
        pacman -S --noconfirm ${unsatisfied[*]} &> /dev/null
        flag=$?
    else
        echo "Ok I don't know what package manager you are using..."
        echo "Make sure you have the following installed: ${unsatisfied[*]}"
        exit
    fi
    if (( $flag == 0 )); then
        echo "Installation of dependencies successful"
    else
        echo "Something went wrong with dependencies installation. Try manually"
    fi
fi

echo "Installing required python dependencies..."
pip3 install -r requirements.txt &> /dev/null
if [ $? -eq 0 ]; then
    echo "Python modules successfully installed"
else
    echo "Something was wrong in python modules... Try installing manually"
fi

exec python3 ProxyDNSConfigCreator.py 

if [ $? -eq 0 ]; then
    echo "The script is now modifing /etc/dnsmasq.conf"
    if [ "/etc/dnsmasq.conf" -f ]; then
        echo "The old file can be found at /etc/dnsmasq.conf.bckup"
        cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bckup
    fi
    mv ./dnsmasq.conf /etc/dnsmasq.conf
else    
    echo "Well something went wrong... It shoulda worked..."
    exit
fi

systemctl start dnsmasq.service
if (( $? == 0 )); then
    echo "DNS Server successfully started"
else
    echo "Starting DNS Server failed"
    echo "If you are using systemd check whether systemd-resolvd is running"
    echo "If it is running, then stop it and start dnsmasq.service again"
fi