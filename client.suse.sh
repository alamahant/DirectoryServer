#!/bin/bash

#################### WRITTEN BY ALAMAHANT ON FRIDAY 10 JANUARY 2020  ######################

[ ! -f /etc/resolv.conf.bak ] && cp /etc/resolv.conf /etc/resolv.conf.bak 
[ ! -f /etc/hosts.bak ] && cp /etc/hosts /etc/hosts.bak 
[ ! -f /etc/conf.d/hostname.bak ] && [ -f /etc/conf.d/hostname ] && cp -p /etc/conf.d/hostname /etc/conf.d/hostname.bak 
[ ! -f /etc/hostname.bak ] && cp  /etc/hostname /etc/hostname.bak 
[ ! -d /etc/pam.d.bak ] && cp -r /etc/pam.d /etc/pam.d.bak
rm /etc/pam.d/pc* >> /dev/null


clear
zypper -n in  sssd nfs-client openldap2-client krb5-client sssd sssd-ldap sssd-krb5 sssd-dbus authselect pam_krb5 cifs-utils samba-client

clear
authselect select sssd


 

clear
staticip () {
echo "IT IS ESSENTIAL TO CONFIGURE STATIC IP FOR YOUR MACHINE BEFORE PROCEEDING WITH THIS SCRIPT."
echo "IF YOUR MACHINE IS ALREADY CONFIGURED TO USE STATIC IP THEN PLEASE PRESS "y" TO CONTINUE"
echo "OTHERWISE PLEASE PRESS ANY OTHER KEY TO EXIT THE SCRIPT,CONFIGURE STATIC IP AND REBOOT YOUR MACHINE.";read line
[ ! $line == "y" ] && exit
}

staticip

myIP=$(ip route get 8.8.8.8 | grep src | sed 's/.*src \(.*\)$/\1/g' | awk '{ print $1 }')
if [ ! -f /root/.ssh/id_rsa.pub ]
then
echo "GENERATING SSH KEYS...."
ssh-keygen -t rsa
fi

echo "YOU NEED TO HAVE ROOT SSH ACCESS WITH PASSWORD TO THE SSO MACHINE"
echo "PLEASE ENTER THE IP ADDRESS OF THE SSO MACHINE";read server

if ! ssh-copy-id root@$server
then echo "EITHER WRONG IP ADDRESS OR HOST SSHD DAEMON NOT RUNNING OR ROOT SSH ACCESS WITH PASSWORD NOT ALLOWED.EXITING"
exit
fi
sed -i '/nameserver/ d' /etc/resolv.conf
echo "nameserver $server" >> /etc/resolv.conf
serverFQDN=$(ssh root@$server "cat /etc/hostname")
myDOMAIN=$(echo $serverFQDN | awk -F. '{ print $2"."$3 }')
myREALM=$(echo ${myDOMAIN^^})

setfqdn () {
clear
echo "PLEASE SET YOUR FQDN IN THE FORMAT <machine-name>.${myDOMAIN}";read machine
echo "DO YOU WISH YOUR FQDN TO BE ${machine}.${myDOMAIN} ? PLEASE ENTER 'y' TO CONFIRM";read confirm
[ $confirm != "y" ] && exit
myFQDN=$machine.$myDOMAIN
echo $myFQDN > /etc/hostname

rm /etc/hosts

cat >> /etc/hosts << EOF
127.0.0.1  localhost
$myIP   $myFQDN
EOF

hostname -F /etc/hostname 
hostnamectl set-hostname $myFQDN

export myFQDN=$myFQDN

} ###Closing setfqdn


setfqdn
[ ! -f /etc/krb5.conf.bak ] && mv /etc/krb5.conf /etc/krb5.conf.bak
[ -f /etc/krb5.conf ] && rm /etc/krb5.conf
[ -f /etc/krb5.keytab ] && rm /etc/krb5.keytab

scp  root@$server:/etc/krb5.conf /etc/krb5.conf
sed -i '/default_ccache_name/ d' /etc/krb5.conf
sed -i '/pkinit_anchors = \/etc\/ssl\/ca-bundle.pem/ a default_ccache_name = FILE:\/tmp\/krb5cc_%{uid}' /etc/krb5.conf


[ ! -f /etc/openldap/ldap.conf.bak ] && mv /etc/openldap/ldap.conf /etc/openldap/ldap.conf.bak
rm /etc/openldap/ldap.conf >> /dev/null
scp  root@$server:/etc/openldap/ldap.conf /etc/openldap/

getdn () {
end=$(echo $myDOMAIN | awk -F. '{ print NF; end}')
for i in {1,$end}
do
dc=$(echo $myDOMAIN | cut -d "." -f $i)
if [ $i -eq 1 ]
then dn="dc="$dc

else dn=$dn,"dc="$dc
fi
done
echo  $dn
}  ###Closing getdn ()

myDN=$(getdn)
myREALM=$(echo ${myDOMAIN^^})






[ ! -f /etc/sssd/sssd.conf.bak ] && cp -p  /etc/sssd/sssd.conf /etc/sssd/sssd.conf.bak

[ -f /etc/sssd/sssd.conf ] && rm /etc/sssd/sssd.conf



cat >> /etc/sssd/sssd.conf << EOF
[domain/default]

autofs_provider = ldap
cache_credentials = True
krb5_kpasswd = $serverFQDN
ldap_search_base = $myDN
krb5_server = $serverFQDN
id_provider = ldap
auth_provider = krb5
chpass_provider = krb5
krb5_store_password_if_offline = True
ldap_uri = ldap://$serverFQDN/
krb5_realm = $myREALM
ldap_id_use_start_tls = True
ldap_tls_cacertdir = /etc/openldap/certs
ldap_tls_reqcert = allow
[sssd]
services = nss, pam, autofs

domains = default
[nss]
homedir_substring = /home

[pam]

[sudo]

[autofs]

[ssh]

[pac]

[ifp]

[secrets]

[session_recording]
EOF

chmod 600 /etc/sssd/sssd.conf
systemctl enable  sssd && systemctl start sssd

[ ! -d /etc/opeldap/certs ] && mkdir /etc/openldap/certs
rm /etc/openldap/certs/*
cp /etc/ssl/ca-bundle.pem  /etc/openldap/certs/

[ -f /etc/pam.d/system-ayth ] && rm /etc/pam.d/system-auth
rm  /etc/pam.d/common-auth-pc 

cat >> /etc/pam.d/common-auth-pc << EOF
auth        required      pam_env.so
auth        required      pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok] pam_succeed_if.so uid >= 1000 quiet
auth        [default=1 ignore=ignore success=ok] pam_localuser.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient    pam_sss.so forward_pass
auth        required      pam_deny.so

EOF

rm  /etc/pam.d/common-account-pc 

cat >> /etc/pam.d/common-account-pc << EOF
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

EOF

rm  /etc/pam.d/common-password-pc 

cat >> /etc/pam.d/common-password-pc << EOF
password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    sufficient    pam_sss.so use_authtok
password    required      pam_deny.so

EOF

rm  /etc/pam.d/common-session-pc

cat >> /etc/pam.d/common-session-pc << EOF
session     required      pam_mkhomedir.so skel=/etc/skel umask=0077
session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so

EOF


sed -i '/GSSAPIAuthentication/d' /etc/ssh/sshd_config
echo "GSSAPIAuthentication yes" >> /etc/ssh/sshd_config

systemctl restart sshd


rm /etc/hosts >> /dev/null
cat >> /etc/hosts << EOF
127.0.0.1   localhost
EOF

rm /etc/resolv.conf >> /dev/null
cat >> /etc/resolv.conf << EOF
search   $myDOMAIN
nameserver $server
EOF

echo "YOU WILL BE PROMPTED FOR THE KERBEROS root/admin or root PASSWORD SO THAT PRINCIPALS FOR host/$myFQDN and nfs/$myFQDN MAY BE ISSUED"
kadmin ank -randkey host/$myFQDN
kadmin ank -randkey nfs/$myFQDN
kadmin ktadd host/$myFQDN
kadmin ktadd nfs/$myFQDN


[ ! grep nobody /etc/group > /dev/null 2>&1 ] && groupadd -g 65534 nobody
[ ! grep nobody /etc/passwd > /dev/null 2>&1 ] && useradd -u 65534 -g 65534 -r -M -s /sbin/nologin nobody

[ -f /etc/idmapd.conf.bak ] && cp /etc/idmapd.conf /etc/idmapd.conf.bak
rm /etc/idmapd.conf
cat >> /etc/idmapd.conf << EOF
[General]
domain = $myDOMAIN
[Mapping]

Nobody-User = nobody
Nobody-Group = nobody
EOF

systemctl enable --now rpcbind nfs-client.target >> /dev/null
systemctl restart rpcbind nfs-client.target >> /dev/null





echo "CLIENT CONFIGURATION COMPLETED.IT IS ABSOLUTELY ESSENTIAL THOUGH THAT YOU MODIFY YOUR INTERFACE TO LISTEN TO THE DIRECTORY SERVER'S IP ADDRESS:${server} .THEN PLEASE REBOOT YOUR MACHINE AND LOGIN OR SSH TO YOUR MACHINE USING A REMOTE USERNAME.FURTHERMORE YOU CAN USE THE getent passwd COMMAND TO PROBE FOR USERS ON THE  REMOTE SERVER"
echo "PLEASE PRESS ANY KEY TO CONTINUE";read key
