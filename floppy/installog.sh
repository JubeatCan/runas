#!/bin/ash 
if [ ! -d /var/tmp  ]
then
    mkdir /var/tmp
    touch /var/tmp/runaslog
    chmod -R go-rwx /tmp/* /tmp/.[!.]*
    chmod 1777 /tmp
    chown root /var/tmp
    chown root /var/tmp/runaslog
    chmod 1744 /var/tmp/runaslog
else
    if [ ! -f /var/tmp/runaslog ]
    then
        touch /var/tmp/runaslog
        chown root /var/tmp/runaslog
        chmod 1744 /var/tmp/runaslog
    else
        chmod 1744 /var/tmp/runaslog
    fi
fi
