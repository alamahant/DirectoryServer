#!/bin/bash

#################### WRITTEN BY ALAMAHANT ON FRIDAY 10 JANUARY 2020  ######################

[ ! -f /etc/resolv.conf.bak ] && cp /etc/resolv.conf /etc/resolv.conf.bak 
[ ! -f /etc/hosts.bak ] && cp /etc/hosts /etc/hosts.bak 
[ ! -f /etc/conf.d/hostname.bak ] && [ -f /etc/conf.d/hostname ] && cp -p /etc/conf.d/hostname /etc/conf.d/hostname.bak 
[ ! -f /etc/hostname.bak ] && cp  /etc/hostname /etc/hostname.bak 
[ -f /etc/krb5.conf ] && rm /etc/krb5.conf
[ -f /etc/krb5.keytab ] && rm /etc/krb5.keytab

clear
yum -y update && yum install authconfig sssd nfs-utils openldap-clients krb5-workstation pam_krb5 policycoreutils policycoreutils-python ###checkmodule? 
clear
systemctl enable sshd && systemctl restart sshd

systemctl enable sssd 
 

clear
staticip () {
echo "IT IS ESSENTIAL TO CONFIGURE STATIC IP FOR YOUR MACHINE BEFORE PROCEEDING WITH THIS SCRIPT."
echo "IF YOUR MACHINE IS ALREADY CONFIGURED TO USE STATIC IP THEN PLEASE PRESS "y" TO CONTINUE"
echo "OTHERWISE PLEASE PRESS ANY OTHER KEY TO EXIT THE SCRIPT,CONFIGURE STATIC IP AND REBOOT YOUR MACHINE.";read line
[ ! $line == "y" ] && exit
}

staticip

myIP=$(ip route get 8.8.8.8| grep src | sed 's/.*src \(.*\)$/\1/g' | awk '{ print $1 }')
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
echo $machine $myIP | ssh root@$server xargs  /var/named/dns-record

ssh root@$server << EOF
systemctl reload named

EOF


[ ! -f /etc/krb5.conf.bak ] && mv /etc/krb5.conf /etc/krb5.conf.bak
scp  root@$server:/etc/krb5.conf /etc/krb5.conf
[ ! -f /etc/openldap/ldap.conf.bak ] && mv /etc/openldap/ldap.conf /etc/openldap/ldap.conf.bak
scp  root@$server:/etc/openldap/ldap.conf /etc/openldap/
sed -i 's/TLS_CACERT \/etc\/ssl\/certs\/ca-certificates.crt/TLS_CACERT \/etc\/ssl\/certs\/ca-bundle.crt/g' /etc/openldap/ldap.conf
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

authconfig --enableldap --ldapserver=$serverFQDN --ldapbasedn=$myDN  --enableldapstarttls --enablekrb5 --krb5kdc=$serverFQDN --krb5adminserver=$serverFQDN --krb5realm=$myREALM --enablemkhomedir --update




[ ! -f /etc/sssd/sssd.conf.bak ] && cp -p  /etc/sssd/sssd.conf /etc/sssd/sssd.conf.bak
sed -i '/ldap_tls_cacertdir = "\/etc\/openldap\/cacertsa"/a ldap_tls_reqcert = "allow"' /etc/sssd/sssd.conf

chmod 600 /etc/sssd/sssd.conf
cp /etc/pki/tls/certs/ca-bundle.crt /etc/openldap/cacerts/
#chown ldap. /etc/openldap/cacerts/*

sed -i '/GSSAPIAuthentication yes/d' /etc/ssh/sshd_config
echo "GSSAPIAuthentication yes" >> /etc/ssh/sshd_config

systemctl restart sshd


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



[ -f /etc/idmapd.conf.bak ] && cp /etc/idmapd.conf /etc/idmapd.conf.bak
rm /etc/idmapd.conf
cat >> /etc/idmapd.conf << EOF
[General]
domain = $myDOMAIN
[Mapping]

Nobody-User = nfsnobody
Nobody-Group = nfsnobody
EOF

systemctl enable --now rpcbind nfs nfs-client.target >> /dev/null
systemctl restart rpcbind nfs nfs-client.target >> /dev/null


echo "CONFIGURING SELINUX TO ALLOW CREATION OF REMOTE USERS HOME DIRECTORIES....."

rm mkhomedir.te

cat >> mkhomedir.te << EOF
module mkhomedir 1.0;

require {
        type unconfined_t;
        type oddjob_mkhomedir_exec_t;
        class file entrypoint;
}

#============= unconfined_t ==============
allow unconfined_t oddjob_mkhomedir_exec_t:file entrypoint;
EOF

checkmodule -m -M -o mkhomedir.mod mkhomedir.te
semodule_package --outfile mkhomedir.pp --module mkhomedir.mod
semodule -i mkhomedir.pp


echo "CLIENT CONFIGURATION COMPLETED.IT IS ABSOLUTELY ESSENTIAL THOUGH THAT YOU MODIFY YOUR INTERFACE TO LISTEN TO THE DIRECTORY SERVER'S IP ADDRESS:${server} .THEN PLEASE REBOOT YOUR MACHINE AND LOGIN OR SSH TO YOUR MACHINE USING A REMOTE USERNAME.FURTHERMORE YOU CAN USE THE getent passwd COMMAND TO PROBE FOR USERS ON THE  REMOTE SERVER"
echo "PLEASE PRESS ANY KEY TO CONTINUE";read key
