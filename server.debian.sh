#!/bin/bash


###WRITTEN by alamahant on 24/12/2019
if ! ping -c 1 google.com > /dev/null 2>&1;then echo "No Internet Connectivity,EXITING!!!";exit;fi
apt update && apt install net-tools sipcalc

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

myIP=$(ip route get 8.8.8.8| grep src| sed 's/.*src \(.*\)$/\1/g' | awk '{ print $1 }')

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
myFQDN=$(hostname)


myNETMASK=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $4 }')
myDOMAIN=$(echo $myFQDN | awk -F. '{ print $2"."$3 }')
myMACHINE=$(echo $myFQDN | awk -F. '{ print $1 }')
myINADDR=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F. '{ print $3"."$2"."$1 }')
mySERIAL=$(date '+%Y%m%d'01)
myPTR=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F. '{ print $4 }')
myNETWORK=$(sipcalc $(ip a  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }') | grep "Network address" | awk '{ print $4 }')
myCIDR=$(ip a  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F/ '{ print $2 }')
myDNS=$(ip route | grep default | awk '{ print $3 }')
myREALM=$(echo ${myDOMAIN^^})
myFULLIP=$(ip a | grep inet | grep $myIP | awk '{ print $2 }')
c1=$(echo $myDOMAIN | awk -F. '{ print $1 }')
c2=$(echo $myDOMAIN | awk -F. '{ print $2 }')
c1=$(echo "${c1^}")
c2=$(echo "${c2^}")
c3=$(echo $c1 $c2)

#####DIRECTORIES
myDNSDIR="/etc/bind"
myLDAPCONFDIR="/etc/openldap"
myLDAPDATADIR="/var/lib/ldap"
myKRB5DATADIR="/var/lib/krb5kdc"
myKRB5CONFDIR="/etc/krb5kdc"

###DAEMON NOMENCLATURE
myDNSSVCNAME="named"
myDNSPACKNAME="bind9"
myKDCSVCNAME="krb5kdc"
myKADMINSVCNAME="krb5-admin-server"






dnsinstall () {
clear
echo "PART 1: DNS BIND. PLEASE PRESS ANY KEY TO CONTINUE";read line
cp -p /etc/resolv.conf.bak /etc/resolv.conf

systemctl stop named 

apt remove --purge bind9 
rm -rf $myDNSDIR > /dev/null 2>&1
apt install bind9
clear
cp -p $myDNSDIR/named.conf $myDNSDIR/named.conf.bak
mv $myDNSDIR/named.conf.options $myDNSDIR/named.conf.options.bak
mv  $myDNSDIR/named.conf.local $myDNSDIR/named.conf.local.bak


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

cat >> $myDNSDIR/named.conf.options << EOF

acl "xfer" {
        127.0.0.0/8; $myNETWORK/$myCIDR;

};


acl "trusted" {
        127.0.0.0/8;
        $myNETWORK/$myCIDR;
};


options {
        directory "/etc/bind";
	bindkeys-file "/etc/bind/bind.keys";

        forwarders {
         $myDNS; 8.8.8.8;
         };

        //dnssec-enable yes;
        dnssec-validation no;

        auth-nxdomain no;    # conform to RFC1035
        listen-on-v6 { none; };
        listen-on port 53 { any; };
        allow-query { trusted; };
	allow-query-cache {
                /* Use the cache for the "trusted" ACL. */
                trusted;
        };

        recursion yes;
        allow-recursion { trusted; };
        allow-transfer { xfer; };

};

logging {
        channel default_log {
                file "/var/log/named/named.log" versions 5 size 50M;
                print-time yes;
                print-severity yes;
                print-category yes;
        };

        category default { default_log; };
        category general { default_log; };
        category lame-servers { null; };
};


include "/etc/bind/rndc.key";
controls {
        inet 127.0.0.1 port 953 allow { 127.0.0.1/32; ::1/128; } keys { "rndc-key"; };
};


EOF


cat >> $myDNSDIR/named.conf.local << EOF
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "$myDNSDIR/zones.rfc1918";


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

sed -i 's/OPTIONS="-u bind"/OPTIONS="-4 -u bind"/g' /etc/default/bind9


#sed -i '/nameserver/d' /etc/resolv.conf
sed -i '/search/d' /etc/resolv.conf
echo "search  $myDOMAIN" >> /etc/resolv.conf
#echo "nameserver 127.0.0.1" >> /etc/resolv.conf
rndc-confgen -a
chown -R bind. /etc/bind

[ ! -d /var/log/named ] && mkdir /var/log/named
[ ! -f /var/log/named/named.log ] && touch /var/log/named/named.log
chown -R bind. /var/log/named

rm /etc/hosts
cat >> /etc/hosts << EOF
127.0.0.1  localhost
EOF
systemctl enable named && systemctl restart named

echo "DNS CONFIGURATION COMPLETED.PLEASE REMEMBER TO SET YOUR INTERFACES TO USE THE LOCAL SERVER 127.0.0.1 AS THE PRIMARY DNS SERVER"
echo "PRESS ANY KEY TO CONTUNUE";read line


}    ###closing dnsinstall ()


openldapinstall () {

clear
echo "PART 2: OPENLDAP SERVER.PLEASE PRESS ANY KEY TO CONTINUE";read line

###GET LDAP DN FROM DOMAIN
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


echo "REMOVING PREVIOUS LDAP CONFIG..." 
systemctl stop slapd

apt remove --purge slapd ldap-utils 
rm /var/lib/*mdb > /dev/null 2>&1
rm -rf /etc/ldap > /dev/null 2>&1
[ -f /etc/profile.d/ldapuser.sh ] && rm /etc/profile.d/ldapuser.sh
clear
apt update && apt install slapd ldap-utils
clear
echo "RECONFIGURING OPENLDAP SERVER..."
echo "CREATING SSL CERTIFICATES FOR USE WITH YOUR OPENLDAP SERVER..."
cd /etc/ssl/private
openssl genrsa -aes128 -out server.key 2048
openssl rsa -in server.key -out server.key

echo "PLEASE REMEMBER TO ENTER YOUR FQDN  ${myFQDN} WHEN PROMPTED FOR 'Common Name' PRESS ANY KEY TO CONTINUE";read line
echo "IF YOU GET A invalid_credentials ERROR LATER ON REBOOT YOUR MACHINE AND RERUN THIS SCRIPT"
openssl req -new -days 3650 -key server.key -out server.csr
openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650

cp /etc/ssl/private/server.key \
/etc/ssl/private/server.crt \
/etc/ssl/certs/ca-certificates.crt \
/etc/ldap/sasl2/

chown openldap. /etc/ldap/sasl2/server.key \
/etc/ldap/sasl2/server.crt \
/etc/ldap/sasl2/ca-certificates.crt

mkdir /etc/ldap/ldifs
cd /etc/ldap/ldifs

cat >> basedomain.ldif << EOF
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

ldapadd -x -D cn=admin,${myDN} -W -f basedomain.ldif

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
##!/bin/bash
###Written by alamahant on 24/12/19.This simple script will add A and PTR records to BIND
###Use the script thus "sudo bash dns-record <machine-name>  <IP>".
#[ -z $1 ] || [ -z $2 ] && echo "USAGE dns-record <HOST-NAME> <IP-ADDRESS>" && exit
#myCIDR=$(echo $2 | awk -F. '{ print $4 }')
#myDOMAIN=$(hostname -d)
#mySVCDIR=$myDNSDIR
#mySVCNAME="bind9"
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
#for ((i=1; i<=$(echo $myDOMAIN | awk -F. '{ print NF; end}'); i++))
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
#if ldapadd -x -D cn=admin,$myDN -W -f ldapuser.ldif
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
#for ((i=1; i<=$(echo $myDOMAIN | awk -F. '{ print NF; end}'); i++))
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
#if ldapadd -x -D cn=admin,$myDN -w $adminpasswd  -f ldapuser.ldif
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
olcTLSCACertificateFile: /etc/ldap/sasl2/ca-certificates.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/sasl2/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/sasl2/server.key
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f mod_ssl.ldif


cat >> /etc/ldap/ldap.conf << EOF
BASE   $myDN
URI    ldap://$myFQDN ldaps://$myFQDN ldapi:///

#SIZELIMIT      12
#TIMELIMIT      15
#DEREF          never

# TLS certificates (needed for GnuTLS)
TLS_CACERT      /etc/ssl/certs/ca-certificates.crt
TLS_REQCERT allow
EOF
chown openldap. /etc/ldap/ldap.conf
sed -i '/SLAPD_SERVICES/d' /etc/default/slapd
echo 'SLAPD_SERVICES="ldap:/// ldapi:/// ldaps:///"' >> /etc/default/slapd
systemctl restart slapd


echo "PART 2: OPENLDAP SERVER COMPLETED."
echo "YOU CAN NOW TEST THE FUNCTIONALITY OF YOUR OPENLDAP SERVER BY ISSUING:"
echo "slapcat"
echo "ldapsearch -x -b $myDN -H ldap://$myFQDN/"
echo "ldapsearch -x -D cn=admin,$myDN -b $myDN -H ldaps://$myFQDN/ -W"
echo "ldapsearch -x -b $myDN -H ldapi:///"
echo "etc etc etc"
echo "PLEASE PRESS ANY KEY TO CONTINUE";read line



}   ###closing openldapinstal ()


krb5install () {

clear
echo "PART 3: KERBEROS.PLEASE PRESS ANY KEY TO CONTINUE";read line
echo "REMOVING PREVIOUS KERBEROS CONFIGURATION..."

systemctl stop krb5-kdc krb5-admin-server

apt remove --purge krb5-kdc krb5-admin-server
rm -rf $myKRB5DATADIR/* > /dev/null 2>&1
rm -rf $myKRB5CONFDIR/* > /dev/null 2>&1
rm /etc/krb5.keytab





apt install krb5-kdc krb5-admin-server libpam-krb5 krb5-kdc-ldap

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
	pkinit_anchors = /etc/ssl/certs/ca-certificates.crt
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

[ ! -e $myKRB5CONFDIR/kdc.conf.bak ] && mv $myKRB5CONFDIR/kdc.conf $myKRB5CONFDIR/kdc.conf.bak
rm $myKRB5CONFDIR/kdc.conf > /dev/null 2>&1

cat >> $myKRB5CONFDIR/kdc.conf << EOF
[kdcdefaults]
    kdc_ports = 750,88

[realms]
    $myREALM = {
        database_name = $myKRB5DATADIR/principal
        admin_keytab = FILE:$myKRB5CONFDIR/kadm5.keytab
        acl_file = $myKRB5CONFDIR/kadm5.acl
        key_stash_file = $myKRB5CONFDIR/stash
        kdc_ports = 750,88
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = des3-hmac-sha1
        #supported_enctypes = aes256-cts:normal aes128-cts:normal
        default_principal_flags = +preauth
    }

EOF

rm $myKRB5CONFDIR/kadm5.acl > /dev/null 2>&1
echo "*/admin@${myREALM} *" > $myKRB5CONFDIR/kadm5.acl

kdb5_util create -s -r ${myREALM}
systemctl restart krb5-kdc krb5-admin-server

echo "YOU WILL BE PROMPTED FOR KERBEROS ADMIN USER root/admin PASSWORD.PLEASE PRESS ANY KEY TO CONTINUE";read line
kadmin.local ank root/admin 
kadmin.local ank root 
kadmin.local ank -randkey host/${myFQDN} >> /dev/nul
kadmin.local ank -randkey nfs/${myFQDN} > /dev/null 2>&1
kadmin.local ktadd host/${myFQDN} > /dev/null 2>&1
kadmin.local ktadd nfs/${myFQDN} > /dev/null 2>&1

echo "PART 3: KERBEROS COMPLETED"
echo "YOU MAY USE THE KRB5KDC AND KADMIN SERVERS TO MANAGE YOUR REALM"
echo "SOME USEFUL COMMANDS:"
echo "kadmin.local ank -pw <passwd> <principal>"
echo "kadmin.local ank -randkey host/FQDN"
echo "kadmin.local ktadd service/FQDN"
echo "kadmin.local listprincs"
echo "kadmin.local delprinc <principal>"
echo "PLEASE PRESS ANY KEY TO CONTINUE";read key

} ###Closing krb5installl


nfsinstall () {

clear
echo "PART 4: KERBERISED NFS-SERVER.PLEASE PRESS ANY KEY TO CONTINUE";read line
echo "REMOVING PREVIOUS NFS CONFIGURATION..."

systemctl stop nfs-server rpcbind 

rm -rf /srv/nfs

apt remove --purge nfs-kernel-server

apt install nfs-kernel-server nfs-common

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
Nobody-Group = nogroup
EOF

sed -i '/srv/d' /etc/exports
echo "/srv/nfs *(rw,sec=krb5p,fsid=0,insecure)" >> /etc/exports
echo "/srv/nfs/$nfsDIR *(rw,sec=krb5p,nohide,insecure)" >> /etc/exports

[ ! $(grep 'NEED_GSSD="yes"' /etc/default/nfs-common) ] && sed -i 's/NEED_GSSD=/NEED_GSSD="yes"/g' /etc/default/nfs-common
[ ! $(grep 'NEED_SVCGSSD="yes"' /etc/default/nfs-kernel-server) ] &&  sed -i 's/NEED_SVCGSSD=/NEED_SVCGSSD="yes"/g'  /etc/default/nfs-kernel-server

systemctl restart rpcbind nfs-server

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
apt install samba
echo "REMOVING PREVIOUS SAMBA CONFIGURATION..."
if ! cat /etc/group | grep smbprivate > /dev/null 2>&1;then groupadd -g 3000 smbprivate;fi

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

[ -d /srv/samba ] && rm -rf /srv/samba
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


systemctl restart smbd nmbd
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
apt install ntp
systemctl enable --now ntp && systemctl restart ntp

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
