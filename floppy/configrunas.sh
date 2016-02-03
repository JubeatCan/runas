#!/bin/ash 
if [ ! -f /etc/runas ]
then
    touch /etc/runas
    chown root /etc/runas
    chmod 1711 /etc/runas
else
    chmod 1711 /etc/runas
fi
