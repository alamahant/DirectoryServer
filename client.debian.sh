#!/bin/bash

#################### WRITTEN BY ALAMAHANT ON FRIDAY 10 JANUARY 2020  ######################

[ ! -f /etc/nsswitch.conf ] && cp  /usr/share/libc-bin/nsswitch.conf /etc/nsswitch.conf 
[ ! -f /etc/nsswitch.conf.bak ] && cp  /etc/nsswitch.conf /etc/nsswitch.conf.bak 
[ ! -f /etc/resolv.conf.bak ] && cp /etc/resolv.conf /etc/resolv.conf.bak 
[ ! -f /etc/hosts.bak ] && cp /etc/hosts /etc/hosts.bak 
[ ! -f /etc/conf.d/hostname.bak ] && [ -f /etc/conf.d/hostname ] && cp -p /etc/conf.d/hostname /etc/conf.d/hostname.bak 
[ ! -f /etc/hostname.bak ] && cp  /etc/hostname /etc/hostname.bak 
[ -f /etc/krb5.conf ] && rm /etc/krb5.conf
[ -f /etc/krb5.keytab ] && rm /etc/krb5.keytab
[ ! -f /etc/pam.d/common-auth.bak ] && mv /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
[ ! -f /etc/pam.d/common-password.bak ] && mv /etc/pam.d/common-password /etc/pam.d/common-password.bak
[ ! -f /etc/pam.d/common-account.bak ] && mv /etc/pam.d/common-account /etc/pam.d/common-account.bak
[ ! -f /etc/pam.d/common-session.bak ] && mv /etc/pam.d/common-session /etc/pam.d/common-session.bak
rm /etc/pam.d/common* >> /dev/null

clear

apt update && apt install sssd nfs-common ldap-utils krb5-admin-server libpam-krb5 libnss-sss libpam-sss

clear


systemctl enable sssd 
 

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

serverFQDN=$(ssh root@$server hostname)
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
echo $machine $myIP | ssh root@$server xargs  /etc/bind/dns-record

ssh root@$server << EOF
systemctl reload bind9

EOF


scp  root@$server:/etc/krb5.conf /etc/krb5.conf

[ ! -f /etc/ldap/ldap.conf.bak ] && mv /etc/ldap/ldap.conf /etc/ldap/ldap.conf.bak
rm /etc/ldap/ldap.conf >> /dev/null
scp  root@$server:/etc/ldap/ldap.conf /etc/ldap/

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
ldap_tls_cacertdir = /etc/ldap/sasl2
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

[ ! -d /etc/ldap/sasl2 ] && mkdir /etc/ldap/sasl2
cp /etc/ssl/certs/ca-certificates.crt /etc/ldap/sasl2/

rm /etc/nsswitch.conf
cp -p /etc/nsswitch.conf.bak /etc/nsswitch.conf
sed -i '/passwd/ s/$/ sss/g' /etc/nsswitch.conf
sed -i '/shadow/ s/$/ sss/g' /etc/nsswitch.conf
sed -i '/group/ s/$/ sss/g' /etc/nsswitch.conf

if ! grep automount /etc/nsswitch.conf >> /dev/null
then echo "automount:  files sss" >> /etc/nsswitch.conf
else sed -i '/automount/ s/$/ sss/g' /etc/nsswitch.conf 
fi

if ! grep sudoers /etc/nsswitch.conf >> /dev/null
then echo "sudoers:  files sss" >> /etc/nsswitch.conf
else sed -i '/sudoers/ s/$/ sss/g' /etc/nsswitch.conf 
fi


cat >> /etc/pam.d/common-auth << EOF
auth    [success=2 default=ignore]                      pam_sss.so
auth    [success=1 default=ignore]      pam_unix.so nullok_secure try_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
EOF

cat >> /etc/pam.d/common-account << EOF
account [success=1 new_authtok_reqd=done default=ignore]  pam_unix.so
account requisite                       pam_deny.so
account required                        pam_permit.so
session optional      pam_mkhomedir.so skel=/etc/skel umask=0077
account [default=bad success=ok user_unknown=ignore]    pam_sss.so
EOF

cat >> /etc/pam.d/common-password << EOF
password        sufficient                      pam_sss.so
password        [success=1 default=ignore]      pam_unix.so obscure try_first_pass sha512
password        requisite                       pam_deny.so
password        required                        pam_permit.so
EOF

cat >> /etc/pam.d/common-session << EOF
session [default=1]   pam_permit.so
session requisite     pam_deny.so
session required      pam_permit.so
session optional      pam_mkhomedir.so skel=/etc/skel umask=0077
session optional      pam_sss.so
session required      pam_unix.so 
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



[ -f /etc/idmapd.conf.bak ] && cp /etc/idmapd.conf /etc/idmapd.conf.bak
rm /etc/idmapd.conf
cat >> /etc/idmapd.conf << EOF
[General]
domain = $myDOMAIN
[Mapping]

Nobody-User = nobody
Nobody-Group = nogroup
EOF

systemctl enable --now rpcbind nfs-client.target >> /dev/null
systemctl restart rpcbind nfs-client.target >> /dev/null





echo "CLIENT CONFIGURATION COMPLETED.IT IS ABSOLUTELY ESSENTIAL THOUGH THAT YOU MODIFY YOUR INTERFACE TO LISTEN TO THE DIRECTORY SERVER'S IP ADDRESS:${server} .THEN PLEASE REBOOT YOUR MACHINE AND LOGIN OR SSH TO YOUR MACHINE USING A REMOTE USERNAME.FURTHERMORE YOU CAN USE THE getent passwd COMMAND TO PROBE FOR USERS ON THE  REMOTE SERVER"
echo "PLEASE PRESS ANY KEY TO CONTINUE";read key
