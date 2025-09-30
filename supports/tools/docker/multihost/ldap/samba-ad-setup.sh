#!/bin/bash

set -e

info () {
    echo "[INFO] $@"
}

info "Running setup"

[ -f /var/lib/samba/.setup ] && info "Already setup..." && exit 0

info "Provisioning domain controller..."

info "Given admin password: ${SMB_ADMIN_PASSWORD}"

rm -f /etc/samba/smb.conf

samba-tool domain provision\
 --server-role=dc\
 --use-rfc2307\
 --dns-backend=SAMBA_INTERNAL\
 --realm=ssm.test\
 --domain=test\
 --adminpass=${SMB_ADMIN_PASSWORD}

sed -i '/^\[global\]/a client ldap sasl wrapping = sign\nldap server require strong auth = no\n' /etc/samba/smb.conf
sed -i '/^\[global\]/a client ldap sasl wrapping = sign\nldap server require strong auth = no\n' /etc/samba/smb.conf

cp /etc/samba/smb.conf /var/lib/samba/private/smb.conf
rm -f /etc/samba/smb.conf

touch /var/lib/samba/.setup
