
#!/bin/bash
##########  WRITTEN by alamahant on 9 January 2020 #############

[ ! -f /etc/resolv.conf.bak ] && cp -p /etc/resolv.conf /etc/resolv.conf.bak 
[ ! -f /etc/hosts.bak ] && cp -p /etc/hosts /etc/hosts.bak 
[ ! -f /etc/conf.d/hostname.bak ] && [ -f /etc/conf.d/hostname ] && cp -p /etc/conf.d/hostname /etc/conf.d/hostname.bak 
[ ! -f /etc/hostname.bak ] && cp -p /etc/hostname /etc/hostname.bak 

if ! equery l '*' | grep sipcalc >> /dev/null;then emerge -aq sipcalc;fi 
if ! equery l '*' | grep net-tools >> /dev/null;then emerge -aq net-tools;fi 
if ! equery l '*' | grep gentoolkit >> /dev/null;then emerge -aq app-portage/gentoolkit;fi 

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
#myIP=$(hostname -i)
#myIP=$(ip -o addr show up primary scope global | while read -r num dev fam addr rest; do echo ${addr%/*}; done)
myIP=$(ip route get 8.8.8.8| grep src| sed 's/.*src \(.*\)$/\1/g' | awk '{ print $1 }')
#myFQDN=$(hostname)

setfqdn () {
clear
echo "DO YOU WISH TO SET YOUR FQDN? PLEASE PRESS "y" TO CONFIRM OR IF YOU HAVE ALREADY SET IT PRESS ANY OTHER KEY TO SKIP";read line
[ $line != "y" ] && return 
echo "PLEASE SET YOUR FQDN IN THE FORMAT <machine-name>.<domain>.<dom>";read line
echo "DO YOU WISH YOUR FQDN TO BE ${line}? PLEASE ENTER 'y' TO CONFIRM";read confirm
[ $confirm != "y" ] && exit
echo $line > /etc/hostname&
pidof /sbin/init >> /dev/null && [ -f /etc/conf.d/hostname ] && echo "hostname="$line"" > /etc/conf.d/hostname && echo 'rc_before="net.lo"' >> /etc/conf.d/hostname
rm /etc/hosts

cat >> /etc/hosts << EOF
127.0.0.1  localhost
$myIP   $line
EOF

pidof /sbin/init >> /dev/null && hostname -F /etc/hostname >> /dev/null
pidof /lib/systemd/systemd >> /dev/null && hostnamectl set-hostname $line

} ###Closing setfqdn


setfqdn
myFQDN=$(hostname)

myNETMASK=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $4 }')
#myDOMAIN=$(hostname -d) || myDOMAIN=$(dnsdomainname) || echo "THE SCRIPT ENCOUNTERED AN ERROR AND WILL EXIT.PLEASE FIX THE "hostname" COMMAND BECAUSE IT IS NOT FUNCTIONING PROPERLY"
myDOMAIN=$(echo $myFQDN | awk -F. '{ print $2"."$3 }')
myMACHINE=$(echo $myFQDN | awk -F. '{ print $1 }')
myINADDR=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F. '{ print $3"."$2"."$1 }')
mySERIAL=$(date '+%Y%m%d'01)
myPTR=$(ifconfig  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F. '{ print $4 }')
myNETWORK=$(sipcalc $(ip a  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }') | grep "Network address" | awk '{ print $4 }')
myCIDR=$(ip a  | grep $(echo $myIP | awk '{ print $1 }') | awk '{ print $2 }' | awk -F/ '{ print $2 }')
myDNS=$(ip route | grep default | awk '{ print $3 }')
myREALM=$(echo ${myDOMAIN^^})

c1=$(echo $myDOMAIN | awk -F. '{ print $1 }')
c2=$(echo $myDOMAIN | awk -F. '{ print $2 }')
c1=$(echo "${c1^}")
c2=$(echo "${c2^}")
c3=$(echo $c1 $c2)

#####DIRECTORIES
myDNSDIR="/var/bind"
myLDAPCONFDIR="/etc/openldap"
myLDAPDATADIR="/var/lib/openldap-data"
myKRB5DIR="/var/lib/krb5kdc"
###DAEMON NOMENCLATURE
myDNSSVCNAME="named"
myDNSPACKNAME="bind"
myKDCSVCNAME="mit-krb5kdc"
myKADMINSVCNAME="mit-krb5kadmind"




dnsinstall () {
clear
echo "PART 1: DNS BIND. PLEASE PRESS ANY KEY TO CONTINUE";read line
pidof /lib/systemd/systemd >> /dev/null && systemctl stop $myDNSSVCNAME
pidof /sbin/init >> /dev/null && rc-service $myDNSSVCNAME stop
echo "REMOVING BIND AND PURGING ALL PREVIEWS CONFIGURATION..."
[ -d $myDNSDIR ] && rm  $myDNSDIR/*lan  
[ -d $myDNSDIR ] && rm  $myDNSDIR/*db 
cp /etc/resolv.conf.bak /etc/resolv.conf
echo "INSTALLING AND CONFIGURING BIND..."
if ! equery l '*' | grep net-dns/bind >> /dev/null;then emerge -aq $myDNSPACKNAME;fi
clear
[ ! -f /etc/bind/named.conf.bak ] && mv /etc/bind/named.conf /etc/bind/named.conf.bak
[ -f /etc/bind/named.conf ] && rm /etc/bind/named.conf 
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



$myPTR     IN  PTR       $myFQDN.
EOF

cat >> /etc/bind/named.conf << EOF


acl "xfer" {
	127.0.0.0/8; $myNETWORK/$myCIDR;

};


acl "trusted" {
	127.0.0.0/8;
	$myNETWORK/$myCIDR;
};

options {
	directory "$myDNSDIR";
	pid-file "/run/named/named.pid";

	//bindkeys-file "/etc/bind/bind.keys";

	listen-on-v6 { none; };
	//listen-on { 127.0.0.1; };
	listen-on port 53 { any; };
	allow-query {
		trusted;
	};

	allow-query-cache {
		/* Use the cache for the "trusted" ACL. */
		trusted;
	};

	allow-recursion {
		/* Only trusted addresses are allowed to use recursion. */
		trusted;
	};

	allow-transfer {
		/* Zone tranfers are denied by default. */
		xfer;
	};

	allow-update {
		/* Don't allow updates, e.g. via nsupdate. */
		none;
	};


	forwarders { $myDNS; };

	dnssec-enable yes;
	dnssec-validation no;


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
};


include "/etc/bind/rndc.key";
controls {
	inet 127.0.0.1 port 953 allow { 127.0.0.1/32; ::1/128; } keys { "rndc-key"; };
};

zone "." in {
	type hint;
	file "$myDNSDIR/named.cache";
};

zone "localhost" IN {
	type master;
	file "pri/localhost.zone";
	notify no;
};


zone "${myDOMAIN}" IN {
                type master;
                file "$myDOMAIN.lan";
                allow-update { none; };
        };
zone "${myINADDR}.in-addr.arpa" IN {
                type master;
                file "$myINADDR.db";
                allow-update { none; };
        };

EOF
#######################################

sed -i '/OPTIONS=/d' /etc/conf.d/named
echo 'OPTIONS="-4"' >> /etc/conf.d/named
if pidof /lib/systemd/systemd >> /dev/null
then 
#sed -i 's/ExecStart=\/usr\/sbin\/named -f -u named/ExecStart=\/usr\/sbin\/named -f -4 -u named/g' /etc/systemd/system/named.service
sed -i 's/ExecStart=\/usr\/sbin\/named -f -u named/ExecStart=\/usr\/sbin\/named -f -4 -u named/g' /lib/systemd/system/named.service
systemctl daemon-reload
fi
chown root:named /etc/bind/named.conf
chown root:named $myDNSDIR/*lan
chown root:named $myDNSDIR/*db
rm /etc/hosts
cat >> /etc/hosts << EOF
127.0.0.1  localhost
EOF


[ ! -d /var/log/named ] && mkdir /var/log/named
[ ! -f /var/log/named/named.log ] && touch /var/log/named/named.log && chown named. /var/log/named/named.log
pidof /lib/systemd/systemd >> /dev/null && systemctl enable $myDNSSVCNAME && systemctl restart $myDNSSVCNAME
pidof /sbin/init >> /dev/null && rc-update add $myDNSSVCNAME default && rc-service $myDNSSVCNAME restart
sed -i '/nameserver/d' /etc/resolv.conf
sed -i '/search/d' /etc/resolv.conf
echo "search  $myDOMAIN" >> /etc/resolv.conf
echo "nameserver 127.0.0.1" >> /etc/resolv.conf
clear
echo "DNS CONFIGURATION COMPLETED.PLEASE REMEMBER TO SET YOUR INTERFACES TO USE THE LOCAL SERVER 127.0.0.1 AS THE PRIMARY DNS SERVER"
echo "PRESS ANY KEY TO CONTUNUE";read line
}    ###closing dnsinstall ()


openldapinstall () {
clear
echo "PART 2: OPENLDAP SERVER.PLEASE PRESS ANY KEY TO CONTINUE";read line
clear
pidof /lib/systemd/systemd >> /dev/null && systemctl stop slapd >> /dev/null
pidof /sbin/init >> /dev/null && rc-service slapd stop >> /dev/null
echo "REMOVING PREVIOUS LDAP CONFIG..." 
rm -rf $myLDAPDATADIR/*mdb >> /dev/null
rm -rf $myLDAPCONFDIR/slap.conf >> /dev/null
rm -rf $myLDAPCONFDIR/slapd.d/* >> /dev/null
rm -rf $myLDAPCONFDIR/ssl/* >> /dev/null
rm -rf $myLDAPCONFDIR/ldifs/* >> /dev/null
[ -f /etc/profile.d/ldapuser.sh ] && rm /etc/profile.d/ldapuser.sh
echo "net-nds/openldap kerberos sha2 sasl -minimal samba" > /etc/portage/package.use/openldap
[ -f /etc/conf.d/slapd.bak ] && cp  /etc/conf.d/slapd.bak /etc/conf.d/slapd

 
emerge -DNaq net-nds/openldap

###GET LDAP BASEDN FROM DOMAIN
echo "RECONFIGURING OPENLDAP SERVER..."

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


cp $myLDAPCONFDIR/DB_CONFIG.example $myLDAPCONFDIR/DB_CONFIG >> /dev/null && chown ldap. $myLDAPCONFDIR/DB_CONFIG
cp $myLDAPDATADIR/DB_CONFIG.example $myLDAPDATADIR/DB_CONFIG >> /dev/null && chown ldap. $myLDAPDATADIR/DB_CONFIG

[ ! -f /etc/conf.d/slapd.bak ] && cp -p /etc/conf.d/slapd /etc/conf.d/slapd.bak
[ -f $myLDAPCONFDIR/slapd.conf ] && rm $myLDAPCONFDIR/slapd.conf 

cat >> $myLDAPCONFDIR/slapd.conf << EOF
include		$myLDAPCONFDIR/schema/core.schema
pidfile		/run/openldap/slapd.pid
argsfile	/run/openldap/slapd.args

modulepath	/usr/lib64/openldap/openldap
moduleload	back_passwd.so
moduleload	back_monitor.so
moduleload	back_mdb.so
moduleload	back_ldap.so
moduleload	pw-kerberos.so

database config
access to *
        by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
        by * none

database monitor
access to *
        by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
        by * none

database        mdb
access to *
        by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
        by * none

suffix		"dc=my-domain,dc=com"
maxsize         10485760
checkpoint	32	30 
rootdn		"cn=Manager,dc=my-domain,dc=com"
rootpw		secret
directory	$myLDAPDATADIR

index	objectClass	eq
index   uid             pres,eq
index   mail            pres,sub,eq
index   cn              pres,sub,eq
index   sn              pres,sub,eq
index   dc              eq

EOF
chown root:ldap $myLDAPCONFDIR/slapd.conf

pidof /lib/systemd/systemd >> /dev/null && systemctl enable slapd && systemctl restart slapd 
pidof /sbin/init >> /dev/null && rc-service slapd start 
chown -R ldap. $myLDAPDATADIR

rm /etc/conf.d/slapd >> /dev/null

cat >> /etc/conf.d/slapd << "EOF"
INSTANCE="openldap${SVCNAME#slapd}"
OPTS_CONF="-F /etc/${INSTANCE}/slapd.d"
OPTS="${OPTS_CONF} -h 'ldaps:// ldap:// ldapi://%2fvar%2frun%2fopenldap%2fslapd.sock'"
#rc_need="!net net.lo"
EOF

[ ! -d $myLDAPCONFDIR/slad.d ] && mkdir $myLDAPCONFDIR/slapd.d 
slaptest -f $myLDAPCONFDIR/slapd.conf  -F $myLDAPCONFDIR/slapd.d/ >> /dev/null
chown -R ldap. $myLDAPCONFDIR/slapd.d
chown -R ldap. $myLDAPDATADIR
pidof /lib/systemd/systemd >> /dev/null && systemctl restart slapd
pidof /sbin/init >> /dev/null && rc-update add slapd default && rc-service slapd restart


echo "CREATING SSL CERTIFICATES FOR USE WITH YOUR OPENLDAP SERVER..."
cd /etc/ssl/private
openssl genrsa -aes128 -out server.key 2048
openssl rsa -in server.key -out server.key

clear

echo "PLEASE REMEMBER TO ENTER YOUR FQDN  ${myFQDN} WHEN PROMPTED FOR 'Common Name' PRESS ANY KEY TO CONTINUE";read line
openssl req -new -days 3650 -key server.key -out server.csr
openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650
[ ! -d $myLDAPCONFDIR/ssl ] && mkdir $myLDAPCONFDIR/ssl

cp /etc/ssl/private/server* $myLDAPCONFDIR/ssl/
cp /etc/ssl/certs/ca-certificates.crt $myLDAPCONFDIR/ssl/
chown -R ldap. $myLDAPCONFDIR/ssl

[ ! -d $myLDAPCONFDIR/ldifs ] && mkdir $myLDAPCONFDIR/ldifs
cd $myLDAPCONFDIR/ldifs

clear
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
#mySVCDIR="/var/bind"
#mySVCNAME="named"
#if ! $(cat $mySVCDIR/*lan | grep $1 >> /dev/null)  && ! $(cat $mySVCDIR/*lan | grep $2 >> /dev/null)  
#then 
#echo "$1    IN A      $2" >> $mySVCDIR/*lan
#echo "$myCIDR    IN PTR      $1.$myDOMAIN" >> $mySVCDIR/*db
#pidof /lib/systemd/systemd >> /dev/null && systemctl reload $mySVCNAME
#pidof /sbin/init >> /dev/null && service $mySVCNAME reload
#echo "Host $1 with IP $2 added to Bind"
#elif $(cat $mySVCDIR/*lan | grep $1 >> /dev/null)
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
#if kadmin.local listprincs | grep  ${givenName}.${sn} >> /dev/null
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
#if kadmin.local listprincs | grep  ${givenName}.${sn} >> /dev/null
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
olcTLSCACertificateFile: $myLDAPCONFDIR/ssl/ca-certificates.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: $myLDAPCONFDIR/ssl/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: $myLDAPCONFDIR/ssl/server.key
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f mod_ssl.ldif

sleep 3

rm $myLDAPCONFDIR/ldap.conf >> /dev/null
cat >> $myLDAPCONFDIR/ldap.conf << EOF
BASE   $myDN
URI    ldap://$myFQDN ldaps://$myFQDN ldapi:///

#SIZELIMIT      12
#TIMELIMIT      15
#DEREF          never

# TLS certificates (needed for GnuTLS)
TLS_CACERT      /etc/ssl/certs/ca-certificates.crt
TLS_REQCERT allow
EOF

chown ldap. $myLDAPCONFDIR/ldap.conf

pidof /lib/systemd/systemd >> /dev/null && systemctl restart slapd
pidof /sbin/init >> /dev/null && rc-service slapd restart

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

echo "app-crypt/mit-krb5  openldap" > /etc/portage/package.use/mit-krb5
pidof /lib/systemd/systemd >> /dev/null && systemctl stop $myKDCSVCNAME $myKADMINSVCNAME
pidof /sbin/init >> /dev/null && rc-service $myKDCSVCNAME stop && rc-service $myKADMINSVCNAME stop

rm -rf $myKRB5DIR/* >> /dev/null

emerge -DNaq mit-krb5
echo "RECONFIGURING KERBEROS..."

[ ! -e /etc/krb5.conf.bak ] && cp /etc/krb5.conf /etc/krb5.conf.bak
rm /etc/krb5.conf >> /dev/null
rm /etc/krb5.keytab >> /dev/null


cat >> /etc/krb5.conf << EOF
[libdefaults]
	default_realm = $myREALM
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

cat >> $myKRB5DIR/kdc.conf << EOF
[kdcdefaults]
    kdc_ports = 750,88

[realms]
    $myREALM = {
        database_name = $myKRB5DIR/principal
        admin_keytab = FILE:$myKRB5DIR/kadm5.keytab
        acl_file = $myKRB5DIR/kadm5.acl
        key_stash_file = $myKRB5DIR/stash
        kdc_ports = 750,88
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = des3-hmac-sha1
        #supported_enctypes = aes256-cts:normal aes128-cts:normal
        default_principal_flags = +preauth
    }

EOF

echo "*/admin@${myREALM} *" > $myKRB5DIR/kadm5.acl
echo "YOU WILL BE PROMPTED FOR KERBEROS DB ROOT PASSWD.PLEASE PRESS ANY KEY TO CONTINUE";read line
kdb5_util create -s -r ${myREALM}
pidof /lib/systemd/systemd >> /dev/null && systemctl enable $myKDCSVCNAME $myKADMINSVCNAME  && systemctl restart $myKDCSVCNAME $myKADMINSVCNAME
pidof /sbin/init >> /dev/null && rc-update add $myKDCSVCNAME default && rc-update add  $myKADMINSVCNAME default && rc-service $myKDCSVCNAME restart && rc-service $myKADMINSVCNAME restart
kadmin.local ank -randkey host/${myFQDN} >> /dev/nul
kadmin.local ktadd host/${myFQDN} >> /dev/null
echo "YOU WILL BE PROMPTED FOR KERBEROS ADMIN USER root/admin PASSWORD.PLEASE PRESS ANY KEY TO CONTINUE";read line
kadmin.local ank root/admin 
kadmin.local ank root 
clear
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
pidof /lib/systemd/systemd >> /dev/null && systemctl stop nfs-server rpcbind 
pidof /sbin/init >> /dev/null && rc-service nfs stop && rc-service rpcbind stop
rm -rf /srv/nfs
echo "net-fs/nfs-utils kerberos ldap nfsv4" > /etc/portage/package.use/nfs-utils
echo "net-libs/libtirpc kerberos" > /etc/portage/package.use/libtirpc
 
emerge -DNaq nfs-utils
echo "RECONFIGURING NFS-SERVER..."

###########################
nfsdir () {
echo 'NFS SERVER WILL SHARE A PRIVATE DIRECTORY WITH KERBEROS SECURITY sec=krb5p UNDER "/srv/nfs".PLEASE CHOOSE THE DESIRED NAME FOR THIS DIRECTORY';read private
echo "NFS SERVER WILL SHARE "/srv/nfs/$private" PLEASE PRESS "y" TO CONFIRM";read line
[ ! $line == "y" ] && nfsdir
export nfsDIR=${private}
}  ####Closing nfsdir
nfsdir

##########################

sed -i '/srv/d' /etc/exports
mkdir -p /srv/nfs/$nfsDIR >> /dev/null && chmod -R 777 /srv/nfs >> /dev/null
[ ! -f /etc/idmapd.conf.bak ] && mv  /etc/idmapd.conf /etc/idmapd.conf.bak
rm /etc/idmapd.conf

################################
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
echo "/srv/nfs *(rw,sec=krb5p,fsid=0,insecure)" >> /etc/exports
echo "/srv/nfs/$nfsDIR *(rw,sec=krb5p,nohide,insecure)" >> /etc/exports
[ ! -f /etc/conf.d/nfs.bak ] && cp -p /etc/conf.d/nfs /etc/conf.d/nfs.bak
sed -i '/NFS_NEEDED_SERVICES=/d' /etc/conf.d/nfs
echo "NFS_NEEDED_SERVICES="rpc.idmapd rpc.gssd rpc.svcgssd"" >> /etc/conf.d/nfs
pidof /lib/systemd/systemd >> /dev/null && systemctl enable --now rpcbind nfs-server && systemctl restart rpcbind nfs-server
if pidof /sbin/init >> /dev/null
then
rc-update add rpcbind default
rc-update add nfs default
rc-update add nfsclient default
rpc.idmapd
rpc.svcgssd
rc-service nfs restart
rpc.gssd
rc-service nfsclient restart
fi
exportfs -avr
kadmin.local ank -randkey nfs/${myFQDN} >> /dev/null
kadmin.local ktadd nfs/${myFQDN} >> /dev/null
clear
echo "PART 4: KERBERISED NFS-SERVER COMPLETED"
echo "AFTER REBOOTING YOUR MACHINE YOU CAN MOUNT /srv/nfs/$nfsDIR BY ISSUING:"
echo "kinit"
echo "systemctl start nfs-client.target"
echo "mount -t nfs4 -o sec=krb5p ${myFQDN}:/$nfsDIR /mnt"
echo "PLEASE REMEMBER TO CREATE PRINCIPALS FOR YOUR USERS IN KERBEROS."
echo "PLEASE PRESS ANY KEY TO CONTINUE";read line


}  ###Closing nfsinstall
###########################

##########################
sambainstall () {
clear
echo "PART 5: SAMBA SERVER CONFIGURATION.............."
emerge -DNaq samba
echo "REMOVING PREVIOUS SAMBA CONFIGURATION..."
if ! cat /etc/group | grep smbprivate >> /dev/null;then groupadd -g 3000 smbprivate;fi

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
if pidof /lib/systemd/systemd >> /dev/null
then
systemctl enable --now smbd nmbd
systemctl restart smbd nmbd
sleep 3
fi

if pidof /sbin/init >> /dev/null
then
rc-update add samba default
rc-service samba restart
sleep 3
fi


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
if ! equery l '*' | grep net-misc/ntp >> /dev/null;then emerge -DNaq net-misc/ntp;fi
if pidof /lib/systemd/systemd >> /dev/null;then systemctl enable --now ntpd && systemctl restart ntpd;fi
if pidof /sbin/init >> /dev/null
then
rc-update add ntpd default
rc-service ntpd restart
fi

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
