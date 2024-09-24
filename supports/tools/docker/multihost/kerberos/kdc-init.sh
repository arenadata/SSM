#!/bin/bash


echo "==== Add appuser ========="
adduser appuser
echo ""

echo "==== Kerberos KDC and Kadmin ========"
KADMIN_PRINCIPAL_FULL=$KADMIN_PRINCIPAL@$REALM
echo "REALM: $REALM"
echo "KADMIN_PRINCIPAL_FULL: $KADMIN_PRINCIPAL_FULL"
echo "KADMIN_PASSWORD: $KADMIN_PASSWORD"
echo ""

echo "==== Creating realm ========"
/usr/sbin/kdb5_util create -s -r $REALM -P $MASTER_PASSWORD
echo ""

echo "==== Creating default principals in the acl ==========="
echo "Adding $KADMIN_PRINCIPAL principal"
kadmin.local -q "delete_principal -force $KADMIN_PRINCIPAL_FULL"
kadmin.local -q "addprinc -pw $KADMIN_PASSWORD $KADMIN_PRINCIPAL_FULL"
echo ""

echo "==== Creating SSM, HDFS and YARN principals =========="
kadmin.local -q "add_principal -randkey namenode/hadoop-namenode.demo@DEMO"
kadmin.local -q "add_principal -randkey datanode/hadoop-datanode.demo@DEMO"
kadmin.local -q "add_principal -randkey HTTP/ssm-server.demo@DEMO"
kadmin.local -q "add_principal -randkey HTTP/hadoop-datanode.demo@DEMO"
kadmin.local -q "add_principal -randkey ssm/ssm-server.demo@DEMO"
kadmin.local -q "add_principal -randkey agent/hadoop-datanode.demo@DEMO"
kadmin.local -q "add_principal -randkey agent/ssm-server.demo@DEMO"
kadmin.local -q "add_principal -randkey yarn/hadoop-namenode.demo@DEMO"
kadmin.local -q "add_principal -pw krb_pass1 krb_user1@DEMO"
kadmin.local -q "add_principal -pw krb_pass2 krb_user2@DEMO"
echo ""

echo "==== Remove old keytabs  =========="
rm -rf /tmp/secrets/*.keytab
echo ""

echo "==== Export keytabs for SSM, HDFS and YARN =========="
kadmin.local -q "xst -kt /tmp/secrets/namenode.keytab namenode/hadoop-namenode.demo@DEMO" && chown appuser:appuser /tmp/secrets/namenode.keytab
kadmin.local -q "xst -kt /tmp/secrets/datanode.keytab datanode/hadoop-datanode.demo@DEMO" && chown appuser:appuser /tmp/secrets/datanode.keytab
kadmin.local -q "xst -kt /tmp/secrets/http.keytab HTTP/ssm-server.demo@DEMO" && chown appuser:appuser /tmp/secrets/http.keytab
kadmin.local -q "xst -kt /tmp/secrets/http.keytab HTTP/hadoop-datanode.demo@DEMO" && chown appuser:appuser /tmp/secrets/http.keytab
kadmin.local -q "xst -kt /tmp/secrets/ssm.keytab ssm/ssm-server.demo@DEMO" && chown appuser:appuser /tmp/secrets/ssm.keytab
kadmin.local -q "xst -kt /tmp/secrets/agent.keytab agent/hadoop-datanode.demo@DEMO" && chown appuser:appuser /tmp/secrets/agent.keytab
kadmin.local -q "xst -kt /tmp/secrets/agent.keytab agent/ssm-server.demo@DEMO" && chown appuser:appuser /tmp/secrets/agent.keytab
kadmin.local -q "xst -kt /tmp/secrets/yarn.keytab yarn/hadoop-namenode.demo@DEMO" && chown appuser:appuser /tmp/secrets/yarn.keytab
echo ""

krb5kdc
kadmind -nofork