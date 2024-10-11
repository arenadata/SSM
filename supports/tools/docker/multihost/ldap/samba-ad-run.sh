#!/bin/bash

set -e

[ -f /var/lib/samba/.setup ] || {
    >&2 echo "[ERROR] Samba is not setup yet, which should happen automatically. Look for errors!"
    exit 127
}

samba -i -s /var/lib/samba/private/smb.conf &

# Update the password policy settings
samba-tool domain passwordsettings set --complexity=off
samba-tool domain passwordsettings set --min-pwd-length=4
samba-tool domain passwordsettings set --history-length=0

sleep 10

set +e
ldapadd -x -H ldap://samba:389 -D "cn=Administrator,CN=Users,DC=ssm,DC=test" -w "$SMB_ADMIN_PASSWORD" -f /opt/ad-scripts/people.ldif
LDAPADD_STATUS=$?
set -e

if [ $LDAPADD_STATUS -ne 0 ]; then
    >&2 echo "[ERROR] ldapadd failed with exit code $LDAPADD_STATUS"
fi

tail -f /dev/null
