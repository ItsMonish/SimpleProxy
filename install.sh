#!/bin/bash

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "This script needs to be run with root"
    exit
fi

unsatisfied=()
if [[ "/usr/bin/python3" -f ]]; then
    echo "Found Python3"
else
    unsatisfied+=(python3)
fi
if [[ "/usr/bin/pip3" -f ]]; then
    echo "Found python3-pip"
else   
    unsatisfied+=(python3-pip)
fi
if [[ "/usr/bin/dnsmasq" -f ]]; then
    echo "Found dnsmasq"
else
    unsatisfied+=(dnsmasq)
fi

if (( ${#unsatisfied[*]} == 0 )); then
    echo "All dependencies are present"
else    
    echo "The following dependencies are not present: ${unsatisfied[*]}"
    echo "Attempting to install them"
    if [[ "/usr/bin/apt" -f ]]; then
        echo "Installing with apt"
        exec apt install ${unsatisfied[*]} &> /dev/null
        flag=$?
    elif [[ "/usr/bin/yum" -f ]]; then
        echo "Installing with yum"
        exec yum install ${unsatisfied[*]} &> /dev/null
        flag=$?
    elif [[ "/usr/bin/dnf" -f ]]; then
        echo "Installing with dnf"
        exec dnf install ${unsatisfied[*]} &> /dev/null
        flag=$?
    elif [[ "/usr/bin/pacman" -f ]]; then
        echo "Installing with pacman"
        exec pacman -S ${unsatisfied[*]} &> /dev/null
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
exec pip3 install -r requirements.txt &> /dev/null
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
        exec cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bckup
    fi
    exec mv ./dnsmasq.conf /etc/dnsmasq.conf
else    
    echo "Well something went wrong... It shoulda worked..."
    exit
fi

exec systemctl start dnsmasq.service
if (( $? == 0 )); then
    echo "DNS Server successfully started"
else
    echo "Starting DNS Server failed"
    echo "If you are using systemd check whether systemd-resolvd is running"
    echo "If it is running, then stop it and start dnsmasq.service again"
fi