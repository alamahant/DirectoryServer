#!/bin/bash

#################### WRITTEN BY ALAMAHANT ON FRIDAY 10 JANUARY 2020  ######################

[ ! -f /etc/nsswitch.conf.bak ] && cp  /etc/nsswitch.conf /etc/nsswitch.conf.bak 
[ ! -f /etc/resolv.conf.bak ] && cp /etc/resolv.conf /etc/resolv.conf.bak 
[ ! -f /etc/hosts.bak ] && cp /etc/hosts /etc/hosts.bak 
[ ! -f /etc/conf.d/hostname.bak ] && [ -f /etc/conf.d/hostname ] && cp -p /etc/conf.d/hostname /etc/conf.d/hostname.bak 
[ ! -f /etc/hostname.bak ] && cp  /etc/hostname /etc/hostname.bak 
[ -f /etc/krb5.conf ] && rm /etc/krb5.conf
[ -f /etc/krb5.keytab ] && rm /etc/krb5.keytab

echo "sys-auth/sssd  nfsv4 samba sudo autofs ssh" > /etc/portage/package.use/sssd
echo "net-misc/openssh kerberos" > /etc/portage/package.use/mit-krb5
echo  "net-fs/nfs-utils kerberos ldap nfsv4" > /etc/portage/package.use/nfs-utils
echo "net-nds/openldap kerberos sha2 sasl minimal samba" > /etc/portage/package.use/openldap
echo "net-libs/libtirpc kerberos" > /etc/portage/package.use/libtirpc
echo "dev-libs/cyrus-sasl  kerberos" > /etc/portage/package.use/cyrus-sasl
clear
emerge -DNaq sssd openssh nfs-utils openldap mit-krb5  pam_krb5
clear
pidof /lib/systemd/systemd >> /dev/null && systemctl enable sshd && systemctl restart sshd
pidof /sbin/init >> /dev/null && rc-update add sshd default && rc-service sshd restart
pidof /lib/systemd/systemd >> /dev/null && systemctl enable sssd 
pidof /sbin/init >> /dev/null && rc-update add sssd default 

clear
staticip () {
echo "IT IS ESSENTIAL TO CONFIGURE STATIC IP FOR YOUR MACHINE BEFORE PROCEEDING WITH THIS SCRIPT."
echo "IF YOUR MACHINE IS ALREADY CONFIGURED TO USE STATIC IP THEN PLEASE PRESS "y" TO CONTINUE"
echo "OTHERWISE PLEASE PRESS ANY OTHER KEY TO EXIT THE SCRIPT,CONFIGURE STATIC IP AND REBOOT YOUR MACHINE.";read line
[ ! $line == "y" ] && exit
}

staticip

myIP=$(ip route get 8.8.8.8| grep src| sed 's/.*src \(.*\)$/\1/g' | awk '{ print $1 }')
if [ ! -f /root/.ssh/id_rsa.pub]
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

setfqdn () {
clear
echo "PLEASE SET YOUR FQDN IN THE FORMAT <machine-name>.${myDOMAIN}";read machine
echo "DO YOU WISH YOUR FQDN TO BE ${machine}.${myDOMAIN} ? PLEASE ENTER 'y' TO CONFIRM";read confirm
[ $confirm != "y" ] && exit
myFQDN=$machine.$myDOMAIN
echo $myFQDN > /etc/hostname
pidof /sbin/init >> /dev/null && [ -f /etc/conf.d/hostname ] && echo "hostname="${myFQDN}"" > /etc/conf.d/hostname && echo 'rc_before="net.lo"' >> /etc/conf.d/hostname
rm /etc/hosts

cat >> /etc/hosts << EOF
127.0.0.1  localhost
$myIP   $myFQDN
EOF

pidof /sbin/init >> /dev/null && hostname -F /etc/hostname >> /dev/null
pidof /lib/systemd/systemd >> /dev/null && hostnamectl set-hostname $myFQDN
export myFQDN=$myFQDN
} ###Closing setfqdn


setfqdn
echo $machine $myIP | ssh root@$server xargs  /etc/bind/dns-record

ssh root@$server << EOF
pidof /lib/systemd/systemd >> /dev/null && systemctl reload named
pidof /sbin/init >> /dev/null && rc-service named reload
EOF


[ ! -f /etc/krb5.conf.bak ] && mv /etc/krb5.conf /etc/krb5.conf.bak
scp  root@$server:/etc/krb5.conf /etc/krb5.conf
[ ! -f /etc/openldap/ldap.conf.bak ] && mv /etc/openldap/ldap.conf /etc/openldap/ldap.conf.bak
scp  root@$server:/etc/openldap/ldap.conf /etc/openldap/

getdn () {
for ((i=1; i<=$(echo $myDOMAIN | awk -F. '{ print NF; end}'); i++))
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
ldap_tls_cacertdir = /etc/ssl/certs/ca-certificates.crt
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

[ -f /etc/pam.d/system-auth.bak ] && mv /etc/pam.d/system-auth /etc/pam.d/system-auth.bak

cat >> /etc/pam.d/system-auth << EOF
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_sss.so use_first_pass                                         #
auth        required      pam_deny.so
  
account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so                         #
account     required      pam_permit.so
  
password    requisite     pam_cracklib.so try_first_pass retry=3
password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok
password    sufficient    pam_sss.so use_authtok                                            #
password    required      pam_deny.so
  
session     required      pam_mkhomedir.so skel=/etc/skel/ umask=0077
session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so        
EOF
sed -i '/GSSAPIAuthentication yes/d' /etc/ssh/sshd_config
echo "GSSAPIAuthentication yes" >> /etc/ssh/sshd_config

pidof /lib/systemd/systemd >> /dev/null && systemctl restart sshd
pidof /sbin/init >> /dev/null && rc-service sshd restart

rm /etc/hosts
cat >> /etc/hosts << EOF
127.0.0.1   localhost
EOF

rm /etc/resolv.conf
cat >> /etc/resolv.conf << EOF
search   $myDOMAIN
nameserver $server
EOF

echo "YOU WILL BE PROMPTED FOR THE KERBEROS root/admin or root PASSWORD SO THAT PRINCIPALS FOR host/$myFQDN and nfs/$myFQDN MAY BE ISSUED"
kadmin ank -randkey host/$myFQDN
kadmin ank -randkey nfs/$myFQDN
kadmin ktadd host/$myFQDN
kadmin ktadd nfs/$myFQDN

[ -f /etc/conf.d/nfs.bak ] && cp /etc/conf.d/nfs /etc/conf.d/nfs.bak
sed -i '/NFS_NEEDED_SERVICES=/d' /etc/conf.d/nfs
echo "NFS_NEEDED_SERVICES="rpc.idmapd rpc.gssd rpc.svcgssd"" >> /etc/conf.d/nfs

[ -f /etc/idmapd.conf.bak ] && cp /etc/idmapd.conf /etc/idmapd.conf.bak
rm /etc/idmapd.conf
cat >> /etc/idmapd.conf << EOF
[General]
domain = $myDOMAIN
[Mapping]

Nobody-User = nobody
Nobody-Group = nobody
EOF

pidof /lib/systemd/systemd >> /dev/null && systemctl enable --now rpcbind nfs-client.target >> /dev/null

if pidof /sbin/init >> /dev/null
then
rc-update add rpcbind default
rc-update add nfsclient default
fi


echo "CLIENT CONFIGURATION COMPLETED.IT IS ABSOLUTELY ESSENTIAL THOUGH THAT YOU MODIFY YOUR INTERFACE TO LISTEN TO THE DIRECTORY SERVER'S IP ADDRESS:${server} .THEN PLEASE REBOOT YOUR MACHINE AND LOGIN OR SSH TO YOUR MACHINE USING A REMOTE USERNAME.FURTHERMORE YOU CAN USE THE getent passwd COMMAND TO PROBE FOR USERS ON THE  REMOTE SERVER"
echo "PLEASE PRESS ANY KEY TO CONTINUE";read key
