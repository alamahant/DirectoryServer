#!/bin/bash

################## WRITTEN BY ALAMAHANT on 09/01/2020 ###########################


if [ ! -f /etc/profile.d/ldapuser.sh ]
then
echo "#/bin/bash" > /etc/profile.d/ldapuser.sh
echo "export uidserial=10001" >> /etc/profile.d/ldapuser.sh
fi
clear
source /etc/profile.d/ldapuser.sh

[ -f ldapuser.ldif ] && rm ldapuser.ldif


echo "ADDING USER WITH UID" $uidserial

myFQDN=$(hostname)
myDOMAIN=$(echo $myFQDN | awk -F. '{ print $2"."$3 }')
myREALM=$(echo ${myDOMAIN^^})
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

addldapuser () {
[ -f ldapuser.ldif ] && rm ldapuser.ldif
echo "first name";read givenName
echo "last name";read sn
echo "password";read passwd
echo "PEASE PRESS "y" TO CONFIRM ADDITION OF USER";read line
[ ! $line == "y" ] && return
myPASS=$(slappasswd -s $passwd)

cat > ldapuser.ldif << EOF
dn: uid=$givenName.$sn,ou=People,$myDN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: $givenName $sn
sn: $sn
givenName: $givenName
userPassword: $myPASS
loginShell: /bin/bash
uidNumber: $uidserial
gidNumber: 10000
homeDirectory: /home/$givenName.$sn

EOF

if ldapadd -x -D cn=Manager,$myDN -W -f ldapuser.ldif
then
let "uidserial=uidserial+1"
sed -i '/export/d' /etc/profile.d/ldapuser.sh
echo "export uidserial=${uidserial}" >> /etc/profile.d/ldapuser.sh && source /etc/profile.d/ldapuser.sh
echo "ADDED LDAP USER" $givenName.$sn
echo "HERE ARE THE DETAILS:"
echo -e "$(slapcat -s uid=$givenName.$sn,ou=People,$myDN)\n"
echo ""

if kadmin.local listprincs | grep  ${givenName}.${sn} >> /dev/null
then echo "KERBEROS PRINCIPAL "$givenName.$sn@$myREALM" ALREADY EXISTS IN THE KERBEROS DATABASE"
else kadmin.local ank -pw ${passwd} ${givenName}.${sn}
echo "ADDED KERBEROS PRINCIPAL" $givenName.$sn@$myREALM
fi

else echo "USER ALREADY EXISTS OR LDAP SERVER MISCONFIGURATION ERROR" && exit 
fi

} ####Closing addldapuser

addldapuser
 
