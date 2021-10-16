#!/bin/bash


###WRITTEN by alamahant on 24/12/2019

if ! ping -c 1 google.com > /dev/null 2>&1;then echo "No Internet Connectivity,EXITING!!!";exit;fi
yum update && yum install net-tools sipcalc

clear

[ ! -f /etc/resolv.conf.bak ] && cp -p /etc/resolv.conf /etc/resolv.conf.bak 
[ ! -f /etc/hosts.bak ] && cp -p /etc/hosts /etc/hosts.bak 
[ ! -f /etc/conf.d/hostname.bak ] && [ -f /etc/conf.d/hostname ] && cp -p /etc/conf.d/hostname /etc/conf.d/hostname.bak 
[ ! -f /etc/hostname.bak ] && cp -p /etc/hostname /etc/hostname.bak 

clear

staticip () {
echo "IT IS ESSENTIAL TO CONFIGURE STATIC IP FOR YOUR MACHINE BEFORE PROCEEDING WITH THIS SCRIPT."
echo "IF YOUR MACHINE IS ALREADY CONFIGURED TO USE STATIC IP THEN PLEASE PRESS "y" TO CONTINUE"
echo "OTHERWISE PLEASE PRESS ANY OTHER KEY TO EXIT THE SCRIPT,CONFIGURE STATIC IP AND REBOOT YOUR MACHINE.";read line
[ ! $line == "y" ] && exit
}

staticip

echo "EXTRACTING NETWORK INFO AND NOMENCLATURE..."

###NETWORK INFO AND NOMENCLATURE

myIP=$(ip route get 8.8.8.8| grep src | sed 's/.*src \(.*\)$/\1/g' | awk '{ print $1 }')

setfqdn () {

clear

echo "DO YOU WISH TO SET YOUR FQDN? PLEASE PRESS "y" TO CONFIRM OR IF YOU HAVE ALREADY SET IT PRESS ANY OTHER KEY TO SKIP";read line
[ $line != "y" ] && return 
echo "PLEASE SET YOUR FQDN IN THE FORMAT <machine-name>.<domain>.<dom>";read line
echo "DO YOU WISH YOUR FQDN TO BE ${line}? PLEASE ENTER 'y' TO CONFIRM";read confirm
[ $confirm != "y" ] && exit
echo $line > /etc/hostname

rm /etc/hosts

cat >> /etc/hosts << EOF
127.0.0.1  localhost
$myIP   $line
EOF

hostname -F /etc/hostname > /dev/null 2>&1
hostnamectl set-hostname $line

} ###Closing setfqdn


setfqdn
myFQDN=$(hostname) || echo "THE SCRIPT ENCOUNTERED AN ERROR AND WILL EXIT.PLEASE FIX THE "hostname" COMMAND BECAUSE IT IS NOT FUNCTIONING PROPERLY"


myNETMASK=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $4 }')
myDOMAIN=$(echo $myFQDN | awk -F. '{ print $2"."$3 }')
myMACHINE=$(echo $myFQDN | awk -F. '{ print $1 }')
myINADDR=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F. '{ print $3"."$2"."$1 }')
mySERIAL=$(date '+%Y%m%d'01)
myPTR=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F. '{ print $4 }')
#myNETWORK=$(sipcalc $(ip a  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }') | grep "Network address" | awk '{ print $4 }')
#myNETWORK=$(echo $myIP | awk -F. '{ print $1"."$2"."$3"."0 }')


getnetwork () {
default_if=$(ip route list | awk '/^default/ {print $5}')
IFS=. read -r i1 i2 i3 i4 <<< "$myIP"
netmask=$(ifconfig $default_if | grep netmask | awk '{ print $4 }')
IFS=. read -r m1 m2 m3 m4 <<< "$netmask"
printf "%d.%d.%d.%d\n" "$((i1 & m1))" "$((i2 & m2))" "$((i3 & m3))" "$((i4 & m4))"

}
myNETWORK=$(getnetwork)

myCIDR=$(ip a  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F/ '{ print $2 }')
myDNS=$(ip route | grep default | awk '{ print $3 }')
myREALM=$(echo ${myDOMAIN^^})

c1=$(echo $myDOMAIN | awk -F. '{ print $1 }')
c2=$(echo $myDOMAIN | awk -F. '{ print $2 }')
c1=$(echo "${c1^}")
c2=$(echo "${c2^}")
c3=$(echo $c1 $c2)

#####DIRECTORIES
myDNSDIR="/var/named"
myLDAPCONFDIR="/etc/openldap"
myLDAPDATADIR="/var/lib/ldap"
myKRB5DATADIR="/var/kerberos/krb5kdc"


###DAEMON NOMENCLATURE
myDNSSVCNAME="named"
myDNSPACKNAME="bind"
myKDCSVCNAME="krb5kdc"
myKADMINSVCNAME="kadmin"



dnsinstall () {

clear

echo "PART 1: DNS BIND. PLEASE PRESS ANY KEY TO CONTINUE";read line
cp -p /etc/resolv.conf.bak /etc/resolv.conf

systemctl stop named

yum remove  bind 

rm $myDNSDIR/*lan > /dev/null 2>&1
rm $myDNSDIR/*db > /dev/null 2>&1

yum install bind

clear

cp -p /etc/named.conf /etc/named.conf.bak


cat >> $myDNSDIR/$myDOMAIN.lan << EOF
\$TTL 86400
@   IN  SOA    $myFQDN. root.$myDOMAIN. (
        $mySERIAL            ;Serial
        3600        ;Refresh
        1800        ;Retry
        604800      ;Expire
        86400       ;Minimum TTL
)

        IN  NS     $myFQDN.
        IN  A       $myIP

        IN  MX 10   $myFQDN.

$myMACHINE     IN  A       $myIP
EOF

cat >> $myDNSDIR/$myINADDR.db << EOF
\$TTL 86400
@   IN  SOA    $myFQDN. root.$myDOMAIN. (
        $mySERIAL            ;Serial
        3600        ;Refresh
        1800        ;Retry
        604800      ;Expire
        86400       ;Minimum TTL
)

        IN  NS     $myFQDN.
	IN  PTR    $myDOMAIN.
        IN  A       $myNETMASK



$myPTR     IN  PTR       $myDOMAIN.
EOF

[ ! -f /etc/named.conf.bak ] && mv /etc/named.conf /etc/named.conf.bak

[ -f /etc/named.conf ] && rm /etc/named.conf 

cat >> /etc/named.conf << EOF

options {

	directory           "$myDNSDIR";
        dump-file           "$myDNSDIR/data/cache_dump.db";
        statistics-file     "$myDNSDIR/data/named_stats.txt";
        memstatistics-file  "$myDNSDIR/data/named_mem_stats.txt";

        forwarders {
         $myDNS; 8.8.8.8;
         };

        dnssec-enable yes;
        dnssec-validation no;

        auth-nxdomain no;    # conform to RFC1035
        listen-on-v6 { none; };
        listen-on port 53 { any; };
        allow-query { localhost; $myNETWORK/$myCIDR; };
        recursion yes;
        allow-recursion { localhost; $myNETWORK/$myCIDR; };
        allow-transfer { localhost; $myNETWORK/$myCIDR; };


        /* Path to ISC DLV key */
        bindkeys-file "/etc/named.iscdlv.key";

        managed-keys-directory "/var/named/dynamic";

        pid-file "/run/named/named.pid";
        session-keyfile "/run/named/session.key";
};


logging {
        channel default_debug {
                file "data/named.run";
                severity dynamic;
        };
};

zone "$myDOMAIN" IN {
                type master;
                file "$myDNSDIR/$myDOMAIN.lan";
                allow-update { none; };
        };
zone "$myINADDR.in-addr.arpa" IN {
                type master;
                file "$myDNSDIR/$myINADDR.db";
                allow-update { none; };
        };

EOF

sed -i '/OPTIONS=/d' /etc/sysconfig/named
echo "OPTIONS="-4 -u named"" >> /etc/sysconfig/named

sed -i '/nameserver/d' /etc/resolv.conf
sed -i '/search/d' /etc/resolv.conf
echo "search  $myDOMAIN" >> /etc/resolv.conf
echo "nameserver 127.0.0.1" >> /etc/resolv.conf

rndc-confgen -a

rm /etc/hosts
cat >> /etc/hosts << EOF
127.0.0.1  localhost
EOF
chown root:named $myDNSDIR/*lan
chown root:named $myDNSDIR/*db
chown root:named /etc/named.conf
chown named. /etc/rndc.key

systemctl enable --now named  && systemctl restart named

echo "DNS CONFIGURATION COMPLETED.PLEASE REMEMBER TO SET YOUR INTERFACES TO USE THE LOCAL SERVER 127.0.0.1 AS THE PRIMARY DNS SERVER"
echo "PRESS ANY KEY TO CONTUNUE";read line


}    ###closing dnsinstall ()


openldapinstall () {

clear
echo "PART 2: OPENLDAP SERVER.PLEASE PRESS ANY KEY TO CONTINUE";read line


###GET LDAP DN FROM DOMAIN

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


echo "REMOVING PREVIOUS LDAP CONFIG..." 
systemctl stop slapd

yum remove openldap-servers 

rm -rf $myLDAPDATADIR > /dev/null 2>&1
rm -rf $myLDAPCONFDIR/slapd.d > /dev/null 2>&1
rm -rf $myLDAPCONFDIR/certs/server* > /dev/null 2>&1
rm -rf $myLDAPCONFDIR/certs/ca-bundle.crt > /dev/null 2>&1
rm -rf $myLDAPCONFDIR/ldifs > /dev/null 2>&1

[ -f /etc/profile.d/ldapuser.sh ] && rm /etc/profile.d/ldapuser.sh

clear

yum install openldap-servers openldap-clients

clear

[ ! -f /etc/sysconfig/slapd.bak] && cp -p /etc/sysconfig/slapd /etc/sysconfig/slapd.bak
cp -p /etc/sysconfig/slapd.bak /etc/sysconfig/slapd

cp /usr/share/openldap-servers/DB_CONFIG.example $myLDAPDATADIR/DB_CONFIG
chown ldap. $myLDAPDATADIR/DB_CONFIG

echo "RECONFIGURING OPENLDAP SERVER..."

systemctl enable slapd && systemctl start slapd

echo "CREATING SSL CERTIFICATES FOR USE WITH YOUR OPENLDAP SERVER..."



cd /etc/pki/tls/private
openssl genrsa -aes128 -out server.key 2048
openssl rsa -in server.key -out server.key

echo "PLEASE REMEMBER TO ENTER YOUR FQDN  ${myFQDN} WHEN PROMPTED FOR 'Common Name' PRESS ANY KEY TO CONTINUE";read line
openssl req -new -days 3650 -key server.key -out server.csr
openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650

cp /etc/pki/tls/private/server.key \
/etc/pki/tls/private/server.crt \
/etc/pki/tls/certs/ca-bundle.crt \
$myLDAPCONFDIR/certs/

chown ldap. $myLDAPCONFDIR/certs/server*
chown ldap. $myLDAPCONFDIR/certs/ca-bundle.crt


mkdir $myLDAPCONFDIR/ldifs
cd $myLDAPCONFDIR/ldifs


echo "YOU WILL BE PROMPTED FOR THE OPENLDAP ADMINISTRATIVE ACCOUNT "cn=Manager,${myDN}"  PASSWORD."
echo "PLEASE PRESS ANY KEY TO CONTINUE";read line
myPASS=$(echo $(slappasswd))

cat >> chrootpw.ldif << EOF
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: $myPASS
EOF

ldapadd -Y EXTERNAL -H ldapi:/// -f chrootpw.ldif
ldapadd -Y EXTERNAL -H ldapi:/// -f $myLDAPCONFDIR/schema/cosine.ldif
ldapadd -Y EXTERNAL -H ldapi:/// -f $myLDAPCONFDIR/schema/nis.ldif
ldapadd -Y EXTERNAL -H ldapi:/// -f $myLDAPCONFDIR/schema/inetorgperson.ldif

cat >> chdomain.ldif << EOF
dn: olcDatabase={1}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
  read by dn.base="cn=Manager,${myDN}" read by * none

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: $myDN

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=Manager,$myDN

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: $myPASS

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by
  dn="cn=Manager,${myDN}" write by anonymous auth by self write by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to * by dn="cn=Manager,${myDN}" write by * read
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f chdomain.ldif

cat >> basedomain.ldif << EOF
dn: $myDN
objectClass: top
objectClass: dcObject
objectclass: organization
o: $c3
dc: $c1

dn: cn=Manager,$myDN
objectClass: organizationalRole
cn: Manager
description: Directory Manager

dn: ou=People,$myDN
objectClass: organizationalUnit
ou: People

dn: ou=Group,$myDN
objectClass: organizationalUnit
ou: Group

dn: ou=sudoers,$myDN
objectClass: organizationalUnit
ou: sudoers

dn: cn=ldapusers,ou=Group,$myDN
objectClass: top
objectClass: posixGroup
gidNumber: 10000
cn: ldapusers      
EOF

ldapadd -x -D "cn=Manager,${myDN}" -W -f basedomain.ldif


cat >> addgroup.lfif << EOF
dn: cn=,ou=Group,$myDN
objectClass: top
objectClass: posixGroup
gidNumber: 
EOF


cat >> adduser.ldif << EOF
dn: uid=,ou=People,dc=,dc=
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: 
sn: 
givenName: 
userPassword: 
loginShell: /bin/bash
uidNumber: 
gidNumber: 10000
homeDirectory: /home/

dn: cn=,ou=Group,dc=,dc=
objectClass: posixGroup
cn: 
gidNumber: 10000
memberUid:
EOF

##############################################

[ -f $myDNSDIR/dns-record ] && rm $myDNSDIR/dns-record
cat >> $myDNSDIR/dns-record << "EOF"
#!/bin/bash
###Written by alamahant on 24/12/19.This simple script will add A and PTR records to BIND
###Use the script thus "sudo bash dns-record <machine-name>  <IP>".
#[ -z $1 ] || [ -z $2 ] && echo "USAGE dns-record <HOST-NAME> <IP-ADDRESS>" && exit
#myCIDR=$(echo $2 | awk -F. '{ print $4 }')
#myDOMAIN=$(hostname -d)
#mySVCDIR="/var/named"
#mySVCNAME="named"
#if ! $(cat $mySVCDIR/*lan | grep $1 > /dev/null 2>&1)  && ! $(cat $mySVCDIR/*lan | grep $2 > /dev/null 2>&1)  
#then 
#echo "$1    IN A      $2" >> $mySVCDIR/*lan
#echo "$myCIDR    IN PTR      $1.$myDOMAIN" >> $mySVCDIR/*db
#systemctl reload $mySVCNAME
#echo "Host $1 with IP $2 added to Bind"
#elif $(cat $mySVCDIR/*lan | grep $1 > /dev/null 2>&1)
#then 
#echo "Host already exists"
#else echo "IP is taken"
#fi
EOF
sed -i 's/^#//g' $myDNSDIR/dns-record
chmod +x $myDNSDIR/dns-record
#########################################################

####################################################
cat >> ldapuser.sh << "EOF"
##!/bin/bash
#
################### WRITTEN BY ALAMAHANT on 09/01/2020 ###########################
#
#
#if [ ! -f /etc/profile.d/ldapuser.sh ]
#then
#echo "#/bin/bash" > /etc/profile.d/ldapuser.sh
#echo "export uidserial=10001" >> /etc/profile.d/ldapuser.sh
#fi
#clear
#source /etc/profile.d/ldapuser.sh
#
#[ -f ldapuser.ldif ] && rm ldapuser.ldif
#
#
#echo "ADDING USER WITH UID" $uidserial
#
#myFQDN=$(hostname)
#myDOMAIN=$(echo $myFQDN | awk -F. '{ print $2"."$3 }')
#myREALM=$(echo ${myDOMAIN^^})
#getdn () {
#end=$(echo $myDOMAIN | awk -F. '{ print NF; end}')
#for i in {1,$end}
#do
#dc=$(echo $myDOMAIN | cut -d "." -f $i)
#if [ $i -eq 1 ]
#then dn="dc="$dc
#
#else dn=$dn,"dc="$dc
#fi
#done
#echo  $dn
#}  ###Closing getdn ()
#
#myDN=$(getdn)
#
#addldapuser () {
#[ -f ldapuser.ldif ] && rm ldapuser.ldif
#echo "first name";read givenName
#echo "last name";read sn
#echo "password";read passwd
#echo "PEASE PRESS "y" TO CONFIRM ADDITION OF USER";read line
#[ ! $line == "y" ] && return
#myPASS=$(slappasswd -s $passwd)
#
#cat > ldapuser.ldif << EOF
#dn: uid=$givenName.$sn,ou=People,$myDN
#objectClass: inetOrgPerson
#objectClass: posixAccount
#objectClass: shadowAccount
#cn: $givenName $sn
#sn: $sn
#givenName: $givenName
#userPassword: $myPASS
#loginShell: /bin/bash
#uidNumber: $uidserial
#gidNumber: 10000
#homeDirectory: /home/$givenName.$sn
#
#EOF
#
#if ldapadd -x -D cn=Manager,$myDN -W -f ldapuser.ldif
#then
#let "uidserial=uidserial+1"
#sed -i '/export/d' /etc/profile.d/ldapuser.sh
#echo "export uidserial=${uidserial}" >> /etc/profile.d/ldapuser.sh && source /etc/profile.d/ldapuser.sh
#echo "ADDED LDAP USER" $givenName.$sn
#echo "HERE ARE THE DETAILS:"
#echo -e "$(slapcat -s uid=$givenName.$sn,ou=People,$myDN)\n"
#echo ""
#
#if kadmin.local listprincs | grep  ${givenName}.${sn} > /dev/null 2>&1
#then echo "KERBEROS PRINCIPAL "$givenName.$sn@$myREALM" ALREADY EXISTS IN THE KERBEROS DATABASE"
#else kadmin.local ank -pw ${passwd} ${givenName}.${sn}
#echo "ADDED KERBEROS PRINCIPAL" $givenName.$sn@$myREALM
#fi
#
#else echo "USER ALREADY EXISTS OR LDAP SERVER MISCONFIGURATION ERROR" && exit 
#fi
#
#} ####Closing addldapuser
#
#addldapuser
# 
EOF
sed -i 's/^#//g' ldapuser.sh
chmod +x ldapuser.sh
##################################################################

####################################################################
cat >> bulkusers.sh << "EOF"
##!/bin/bash
#
################### WRITTEN BY ALAMAHANT on 09/01/2020 ###########################
#if [ ! -f /etc/profile.d/ldapuser.sh ]
#then
#echo "#/bin/bash" > /etc/profile.d/ldapuser.sh
#echo "export uidserial=10001" >> /etc/profile.d/ldapuser.sh
#fi
#
#
#source /etc/profile.d/ldapuser.sh
#
#
#myFQDN=$(hostname)
#myDOMAIN=$(echo $myFQDN | awk -F. '{ print $2"."$3 }')
#myREALM=$(echo ${myDOMAIN^^})
#getdn () {
#end=$(echo $myDOMAIN | awk -F. '{ print NF; end}')
#for i in {1,$end}
#do
#dc=$(echo $myDOMAIN | cut -d "." -f $i)
#if [ $i -eq 1 ]
#then dn="dc="$dc
#
#else dn=$dn,"dc="$dc
#fi
#done
#echo  $dn
#}  ###Closing getdn ()
#
#myDN=$(getdn)
#
#addldapuser () {
#echo "ADDING USER WITH UID" $uidserial
#[ -f ldapuser.ldif ] && rm ldapuser.ldif
##echo "PEASE PRESS "y" TO CONFIRM ADDITION OF USER";read line
##[ ! $line == "y" ] && return
#myPASS=$(slappasswd -s $passwd)
#
#cat > ldapuser.ldif << EOF
#dn: uid=$givenName.$sn,ou=People,$myDN
#objectClass: inetOrgPerson
#objectClass: posixAccount
#objectClass: shadowAccount
#cn: $givenName $sn
#sn: $sn
#givenName: $givenName
#userPassword: $myPASS
#loginShell: /bin/bash
#uidNumber: $uidserial
#gidNumber: 10000
#homeDirectory: /home/$givenName.$sn
#
#EOF
#
#if ldapadd -x -D cn=Manager,$myDN -w $adminpasswd  -f ldapuser.ldif
#then
#let "uidserial=uidserial+1"
#sed -i '/export/d' /etc/profile.d/ldapuser.sh
#echo "export uidserial=${uidserial}" >> /etc/profile.d/ldapuser.sh && source /etc/profile.d/ldapuser.sh
#echo "ADDED LDAP USER" $givenName.$sn
##echo "HERE ARE THE DETAILS:"
##echo -e "$(slapcat -s uid=$givenName.$sn,ou=People,$myDN)\n"
#echo ""
#
#if kadmin.local listprincs | grep  ${givenName}.${sn} > /dev/null 2>&1
#then echo "KERBEROS PRINCIPAL "$givenName.$sn@$myREALM" ALREADY EXISTS IN THE KERBEROS DATABASE"
#else kadmin.local ank -pw ${passwd} ${givenName}.${sn}
#echo "ADDED KERBEROS PRINCIPAL" $givenName.$sn@$myREALM
#echo ""
#fi
#
#else echo "USER ALREADY EXISTS OR LDAP SERVER MISCONFIGURATION ERROR" && exit 
#fi
#
#} ####Closing addldapuser
#
#
#echo "PLEASE PROVIDE THE ABSOLUTE PATH OF THE FILE CONTAINING THE USERS TO BE ADDED TO THE OPENLDAP DATABASE"
#echo "THE FILE SHOULD CONTAIN ONE USER PER LINE IN THE FORMAT:"
#echo "firstname surname password"; read file
#[ ! -f $file ] && echo "NO SUSCH FILE.EXITING......" && exit
#echo "PLEASE PROVIDE THE PASSWORD FOR THE ADMINISTRATIVE ACCOUNT cn=Manager,$myDN"; read adminpasswd
#
#clear
#while read -r line
#do
#givenName=$(echo $line | awk '{ print $1 }')
#sn=$(echo $line | awk '{ print $2 }')
#passwd=$(echo $line | awk '{ print $3 }')
#addldapuser
#done < $file
# 
EOF
sed -i 's/^#//g' bulkusers.sh
chmod +x bulkusers.sh
#################################################################




cat >> mod_ssl.ldif << EOF
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: $myLDAPCONFDIR/certs/ca-bundle.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: $myLDAPCONFDIR/certs/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: $myLDAPCONFDIR/certs/server.key
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f mod_ssl.ldif

sleep 3

rm $myLDAPCONFDIR/ldap.conf > /dev/null 2>&1
cat >> $myLDAPCONFDIR/ldap.conf << EOF
BASE   $myDN
URI    ldap://$myFQDN ldaps://$myFQDN ldapi:///

#SIZELIMIT      12
#TIMELIMIT      15
#DEREF          never

# TLS certificates (needed for GnuTLS)
TLS_CACERT      /etc/pki/tls/certs/ca-bundle.crt
TLS_REQCERT allow
EOF

chown ldap. $myLDAPCONFDIR/ldap.conf
chown -R ldap. $myLDAPCONFDIR/slapd.d
chown -R ldap. $myLDAPDATADIR

rm /etc/sysconfig/slapd

cat >> /etc/sysconfig/slapd << EOF

# Where the server will run (-h option)
# - ldapi:/// is required for on-the-fly configuration using client tools
#   (use SASL with EXTERNAL mechanism for authentication)
# - default: ldapi:/// ldap:///
# - example: ldapi:/// ldap://127.0.0.1/ ldap://10.0.0.1:1389/ ldaps:///
SLAPD_URLS="ldapi:/// ldap:/// ldaps:///"

# Any custom options
#SLAPD_OPTIONS=""

# Keytab location for GSSAPI Kerberos authentication
#KRB5_KTNAME="FILE:/etc/openldap/ldap.keytab"

EOF


systemctl restart slapd


clear
echo "PART 2: OPENLDAP SERVER COMPLETED."
echo "YOU CAN NOW TEST THE FUNCTIONALITY OF YOUR OPENLDAP SERVER BY ISSUING:"
echo "slapcat"
echo "ldapsearch -x -b $myDN -H ldap://$myFQDN/"
echo "ldapsearch -x -D cn=Manager,$myDN -b $myDN -H ldaps://$myFQDN/ -W"
echo "ldapsearch -x -b $myDN -H ldapi:///"
echo "etc etc etc"
echo "PLEASE PRESS ANY KEY TO CONTINUE";read line

}   ###closing openldapinstal ()



krb5install () {

clear
echo "PART 3: KERBEROS.PLEASE PRESS ANY KEY TO CONTINUE";read line
echo "REMOVING PREVIOUS KERBEROS CONFIGURATION..."

systemctl stop krb5kdc kadmin > /dev/null 2>&1

yum remove krb5-server 
rm -rf $myKRB5DATADIR/* > /dev/null 2>&1


yum install krb5-server krb5-workstation

[ ! -f /etc/krb5.conf.bak ] && cp /etc/krb5.conf /etc/krb5.conf.bak
rm /etc/krb5.conf
rm /etc/krb5.keytab

clear

cat >> /etc/krb5.conf << EOF
[libdefaults]
	default_realm = $myREALM

# The following krb5.conf variables are only for MIT Kerberos.
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
	dns_lookup_realm = false
 	ticket_lifetime = 24h
 	renew_lifetime = 7d
 	forwardable = true
 	rdns = false
	pkinit_anchors = /etc/pki/tls/certs/ca-certificates.crt
 	default_ccache_name = KEYRING:persistent:%{uid}

# The following encryption type specification will be used by MIT Kerberos
# if uncommented.  In general, the defaults in the MIT Kerberos code are
# correct and overriding these specifications only serves to disable new
# encryption types as they are added, creating interoperability problems.
#
# The only time when you might need to uncomment these lines and change
# the enctypes is if you have local software that will break on ticket
# caches containing ticket encryption types it doesn't know about (such as
# old versions of Sun Java).

#	default_tgs_enctypes = des3-hmac-sha1
#	default_tkt_enctypes = des3-hmac-sha1
#	permitted_enctypes = des3-hmac-sha1

# The following libdefaults parameters are only for Heimdal Kerberos.
	fcc-mit-ticketflags = true

[realms]
	$myREALM = {
		kdc = $myFQDN
		admin_server = $myFQDN
	}
[domain_realm]
	.$myDOMAIN = $myREALM
	$myDOMAIN = $myREALM

EOF

[ ! -e $myKRB5DATADIR/kdc.conf.bak ] && mv $myKRB5DATADIR/kdc.conf $myKRB5DATADIR/kdc.conf.bak
[ -f $myKRB5DATADIR/kdc.conf ] ^^ rm $myKRB5DATADIR/kdc.conf 

cat >> $myKRB5DATADIR/kdc.conf << EOF
[kdcdefaults]
    kdc_ports = 750,88

[realms]
    $myREALM = {
        database_name = $myKRB5DATADIR/principal
        admin_keytab = FILE:$myKRB5DATADIR/kadm5.keytab
        acl_file = $myKRB5DATADIR/kadm5.acl
        key_stash_file = $myKRB5DATADIR/stash
        kdc_ports = 750,88
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        #master_key_type = des3-hmac-sha1
        supported_enctypes = aes256-cts:normal aes128-cts:normal
        default_principal_flags = +preauth
    }

EOF

rm $myKRB5DATADIR/kadm5.acl > /dev/null 2>&1
echo "*/admin@${myREALM} *" > $myKRB5DATADIR/kadm5.acl

kdb5_util create -s -r ${myREALM}
systemctl enable --now krb5kdc kadmin

echo "YOU WILL BE PROMPTED FOR KERBEROS ADMIN USER root/admin PASSWORD.PLEASE PRESS ANY KEY TO CONTINUE";read line
$myKADMINSVCNAME.local ank root/admin 
$myKADMINSVCNAME.local ank root 
$myKADMINSVCNAME.local ank -randkey host/${myFQDN} >> /dev/nul
$myKADMINSVCNAME.local ank -randkey nfs/${myFQDN} > /dev/null 2>&1
$myKADMINSVCNAME.local ktadd host/${myFQDN} > /dev/null 2>&1
$myKADMINSVCNAME.local ktadd nfs/${myFQDN} > /dev/null 2>&1

echo "PART 3: KERBEROS COMPLETED"
echo "YOU MAY USE THE KRB5KDC AND KADMIN SERVERS TO MANAGE YOUR REALM"
echo "SOME USEFUL COMMANDS:"
echo "$myKADMINSVCNAME.local ank -pw <passwd> <principal>"
echo "$myKADMINSVCNAME.local ank -randkey host/FQDN"
echo "$myKADMINSVCNAME.local ktadd service/FQDN"
echo "$myKADMINSVCNAME.local listprincs"
echo "$myKADMINSVCNAME.local delprinc <principal>"
echo "PLEASE PRESS ANY KEY TO CONTINUE";read key

} ###Closing krb5installl


nfsinstall () {

clear
echo "PART 4: KERBERISED NFS-SERVER.PLEASE PRESS ANY KEY TO CONTINUE";read line
echo "REMOVING PREVIOUS NFS CONFIGURATION..."

systemctl stop nfs-server rpcbind 

[ -d /srv/nfs ] && rm -rf /srv/nfs

yum remove nfs-utils

yum install nfs-utils

clear
nfsdir () {
echo 'NFS SERVER WILL SHARE A PRIVATE DIRECTORY WITH KERBEROS SECURITY sec=krb5p UNDER "/srv/nfs".PLEASE CHOOSE THE DESIRED NAME FOR THIS DIRECTORY';read private
echo "NFS SERVER WILL SHARE "/srv/nfs/$private" PLEASE PRESS "y" TO CONFIRM";read line
[ ! $line == "y" ] && nfsdir
export nfsDIR=${private}
}  ####Closing nfsdir
nfsdir

mkdir -p /srv/nfs/$nfsDIR > /dev/null 2>&1 && chmod -R 777 /srv/nfs > /dev/null 2>&1

[ ! -f /etc/idmapd.conf.bak ] && cp /etc/idmapd.conf /etc/idmapd.conf.bak
rm /etc/idmapd.conf


cat >> /etc/idmapd.conf << EOF
[General]

Verbosity = 0
#Pipefs-Directory = /run/rpc_pipefs
# set your own domain here, if it differs from FQDN minus hostname
Domain = $myDOMAIN

[Mapping]

Nobody-User = nobody
Nobody-Group = nobody
EOF

sed -i '/srv/d' /etc/exports
echo "/srv/nfs *(rw,sec=krb5p,fsid=0,insecure)" >> /etc/exports
echo "/srv/nfs/$nfsDIR *(rw,sec=krb5p,nohide,insecure)" >> /etc/exports


systemctl enable --now  rpcbind nfs-server

exportfs -avr

clear
echo "PART 4: KERBERISED NFS-SERVER COMPLETED"
echo "AFTER REBOOTING YOUR MACHINE YOU CAN MOUNT /srv/nfs/$nfsDIR BY ISSUING:"
echo "kinit"
echo "systemctl start nfs-client.target"
echo "mount -t nfs4 -o sec=krb5p ${myFQDN}:/$nfsDIR /mnt"
echo "PLEASE REMEMBER TO CREATE PRINCIPALS FOR YOUR USERS IN KERBEROS."
echo "PLEASE PRESS ANY KEY TO CONTINUE";read line


}  ###Closing nfsinstall





##########################
sambainstall () {
clear
echo "PART 5: SAMBA SERVER CONFIGURATION.............."

echo "REMOVING PREVIOUS SAMBA CONFIGURATION..."
[ -d /srv/samba ] && rm -rf /srv/samba

if ! cat /etc/group | grep smbprivate > /dev/null 2>&1;then groupadd -g 3000 smbprivate;fi
yum remove  samba

clear

echo "RECONFIGURING SAMBA..."
yum install samba samba-client cifs-utils

clear

sharedir () {
echo 'SAMBA SERVER WILL SHARE A READ-ONLY OPEN-TO ALL DIRECTORY UNDER "/srv/samba".PLEASE CHOOSE THE DESIRED NAME FOR THIS DIRECTORY';read dir
echo "SAMBA SERVER WILL SHARE "/srv/samba/$dir" PLEASE PRESS "y" TO CONFIRM";read line
[ ! $line == "y" ] && sharedir
export smbshare=${dir}
echo 'SAMBA SERVER WILL SHARE A PRIVATE DIRECTORY TO BE USED ONLY BY THE GROUP "smbprivate" UNDER "/srv/samba".PLEASE CHOOSE THE DESIRED NAME FOR THIS DIRECTORY';read private
echo "SAMBA SERVER WILL SHARE "/srv/samba/$private" PLEASE PRESS "y" TO CONFIRM";read line
[ ! $line == "y" ] && sharedir
export smbprivate=${private}
}  ####Closing sharedir
sharedir

myIFACE=$(ip a  | grep $myIP | awk '{ print $2 }')
myHOSTS=$(echo $myNETWORK | awk -F. '{ print $1"."$2"."$3"." }')

[ -f /etc/samba/smb.conf ] && rm /etc/samba/smb.conf

mkdir -p /srv/samba/$smbshare
mkdir -p /srv/samba/$smbprivate

chmod -R 777 /srv/samba

cat >> /etc/samba/smb.conf << EOF
#======================= Global Settings =====================================
[global]

   workgroup = MYGROUP

   server string = Samba Server

   server role = standalone server

   hosts allow =  $myHOSTS 127.

   guest account = nobody

#   log file = /var/log/samba/log.%m

   max log size = 50

   passdb backend = tdbsam

;   include = /etc/samba/smb.conf.%m

   interfaces = $myIFACE 127.0.0.1/24 

;   logon path = \\%L\Profiles\%U

;   wins support = yes

;   wins server = w.x.y.z

;   wins proxy = yes

   dns proxy = no 

;  add user script = /usr/sbin/useradd %u
;  add group script = /usr/sbin/groupadd %g
;  add machine script = /usr/sbin/adduser -n -g machines -c Machine -d /dev/null -s /bin/false %u
;  delete user script = /usr/sbin/userdel %u
;  delete user from group script = /usr/sbin/deluser %u %g
;  delete group script = /usr/sbin/groupdel %g

map to guest = Bad User
server min protocol = SMB3
smb encrypt = desired
unix charset = UTF-8
dos charset = CP932 

load printers = no
  printing = bsd
  printcap name = /dev/null
  disable spoolss = yes
  show add printer wizard = no

#============================ Share Definitions ==============================
[homes]
   comment = Home Directories
   browseable = no
   writable = no
   valid users = %S

# Un-comment the following and create the netlogon directory for Domain Logons
; [netlogon]
;   comment = Network Logon Service
;   path = /var/lib/samba/netlogon
;   guest ok = yes
;   writable = no
;   share modes = no


# Un-comment the following to provide a specific roving profile share
# the default is to use the user's home directory
;[Profiles]
;    path = /var/lib/samba/profiles
;    browseable = no
;    guest ok = yes


# NOTE: If you have a BSD-style print system there is no need to 
# specifically define each individual printer
[printers]
   comment = All Printers
   path = /var/spool/samba
   browseable = no
# Set public = yes to allow user 'guest account' to print
   guest ok = no
   writable = no
   printable = yes

# This one is useful for people to share files
;[tmp]
;   comment = Temporary file space
;   path = /tmp
;   read only = no
;   public = yes

# A publicly accessible directory, but read only, except for people in
# the "staff" group
;[public]
;   comment = Public Stuff
;   path = /home/samba
;   public = yes
;   writable = no
;   printable = no
;   write list = @staff

# Other examples. 
#
# A private printer, usable only by fred. Spool data will be placed in fred's
# home directory. Note that fred must have write access to the spool directory,
# wherever it is.
;[fredsprn]
;   comment = Fred's Printer
;   valid users = fred
;   path = /homes/fred
;   printer = freds_printer
;   public = no
;   writable = no
;   printable = yes

# A private directory, usable only by fred. Note that fred requires write
# access to the directory.
;[fredsdir]
;   comment = Fred's Service
;   path = /usr/somewhere/private
;   valid users = fred
;   public = no
;   writable = yes
;   printable = no

# a service which has a different directory for each machine that connects
# this allows you to tailor configurations to incoming machines. You could
# also use the %U option to tailor it by user name.
# The %m gets replaced with the machine name that is connecting.
;[pchome]
;  comment = PC Directories
;  path = /usr/pc/%m
;  public = no
;  writable = yes

# A publicly accessible directory, read/write to all users. Note that all files
# created in the directory by users will be owned by the default user, so
# any user with access can delete any other user's files. Obviously this
# directory must be writable by the default user. Another user could of course
# be specified, in which case all files would be owned by that user instead.
;[public]
;   path = /usr/somewhere/else/public
;   public = yes
;   only guest = yes
;   writable = yes
;   printable = no

# The following two entries demonstrate how to share a directory so that two
# users can place files there that will be owned by the specific users. In this
# setup, the directory should be writable by both users and should have the
# sticky bit set on it to prevent abuse. Obviously this could be extended to
# as many users as required.
;[myshare]
;   comment = Mary's and Fred's stuff
;   path = /usr/somewhere/shared
;   valid users = mary fred
;   public = no
;   writable = yes
;   printable = no
;   create mask = 0765

[$smbprivate]
path = /srv/samba/$smbprivate
guest ok = no
valid users = root @smbprivate
writable = yes
write list = root @smbprivate
create mask = 0664
force create mode = 0644
directory mask = 2775
force directory mode = 2775

[$smbshare]
path = /srv/samba/$smbshare
guest ok = yes
guest only = yes
read only = yes
create mode = 0777
directory mode = 0777


EOF


systemctl enable --now smb nmb
sleep 3

clear
echo "SAMBA CONFIGURATION COMPLETED.PLEASE REMEMBER TO ADD USERS TO THE "smbprivate" GROUP WITH  gid 3000 TO ENABLE THEM TO ACCESS THE $smbprivate DIRECTORY"
echo "MAKE SURE TO ADD THIS GROUP TO ALL CLIENT MACHINES THAT NEED ACCESS TO THE $smbprivate DIRECTORY"
echo "PLEASE USE smbpasswd -a TO ADD USERS TO SAMBA"
echo "PRESS ANY KEY TO CONTINUE";read line

}   ###Closing sambainstall

################################################

##############################
ntpinstall () {
clear
echo "INSTALLING NTP TIME SERVER..."
yum install ntp
systemctl enable --now ntpd 
hwclock --systohc
sleep 3
clear
echo "NTP TIME SERVER INSTALLATION COMPLETE.PLEASE PRESS ANY KEY TO CONTINUE";read line
}  ############Closing ntpinstall()
#####################################




dnsinstall
openldapinstall
krb5install
nfsinstall
sambainstall
ntpinstall


if systemctl is-active firewalld 
then
echo "OPENING PORTS TO FIREWALLD....."
firewall-cmd --add-service={rpc-bind,nfs,nfs3,ssh,ldap,ldaps,kerberos,kadmin,kpasswd,klogin,samba,samba-client,dns,ntp} --permanent > /dev/null 2>&1
firewall-cmd --reload > /dev/null 2>&1
echo "PRESS ANY KEY TO CONTINUE";read key
clear
fi
