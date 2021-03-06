#!/bin/bash

################## WRITTEN BY ALAMAHANT on 09/01/2020 ###########################
if [ ! -f /etc/profile.d/ldapuser.sh ]
then
echo "#/bin/bash" > /etc/profile.d/ldapuser.sh
echo "export uidserial=10001" >> /etc/profile.d/ldapuser.sh
fi


source /etc/profile.d/ldapuser.sh


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
echo "ADDING USER WITH UID" $uidserial
[ -f ldapuser.ldif ] && rm ldapuser.ldif
#echo "PEASE PRESS "y" TO CONFIRM ADDITION OF USER";read line
#[ ! $line == "y" ] && return
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

if ldapadd -x -D cn=Manager,$myDN -w $adminpasswd  -f ldapuser.ldif
then
let "uidserial=uidserial+1"
sed -i '/export/d' /etc/profile.d/ldapuser.sh
echo "export uidserial=${uidserial}" >> /etc/profile.d/ldapuser.sh && source /etc/profile.d/ldapuser.sh
echo "ADDED LDAP USER" $givenName.$sn
#echo "HERE ARE THE DETAILS:"
#echo -e "$(slapcat -s uid=$givenName.$sn,ou=People,$myDN)\n"
echo ""

if kadmin.local listprincs | grep  ${givenName}.${sn} >> /dev/null
then echo "KERBEROS PRINCIPAL "$givenName.$sn@$myREALM" ALREADY EXISTS IN THE KERBEROS DATABASE"
else kadmin.local ank -pw ${passwd} ${givenName}.${sn}
echo "ADDED KERBEROS PRINCIPAL" $givenName.$sn@$myREALM
echo ""
fi

else echo "USER ALREADY EXISTS OR LDAP SERVER MISCONFIGURATION ERROR" && exit 
fi

} ####Closing addldapuser


echo "PLEASE PROVIDE THE ABSOLUTE PATH OF THE FILE CONTAINING THE USERS TO BE ADDED TO THE OPENLDAP DATABASE"
echo "THE FILE SHOULD CONTAIN ONE USER PER LINE IN THE FORMAT:"
echo "firstname surname password"; read file
[ ! -f $file ] && echo "NO SUSCH FILE.EXITING......" && exit
echo "PLEASE PROVIDE THE PASSWORD FOR THE ADMINISTRATIVE ACCOUNT cn=Manager,$myDN"; read adminpasswd

clear
while read -r line
do
givenName=$(echo $line | awk '{ print $1 }')
sn=$(echo $line | awk '{ print $2 }')
passwd=$(echo $line | awk '{ print $3 }')
addldapuser
done < $file
 
