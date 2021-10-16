# DirectoryServer

DIRECTORY SERVER INSTALLATION SCRIPT

A full Directory Server including:

Bind Dns
Openldap
Kerberos
Kerberised NFS
Samba and
NTP

It will use "ip" "ifconfig" "sipcalc" and "hostname" to FIRST extract and variable-ize all your network info and then install and configure:

1.DNS BIND name server with forward and reverse lookup zones all reflecting your network configuration of course.

2. OPENLDAP server.

It will start the server with the stock slapd.conf file and then will switch to OLC functional mode.
It will create the config monitor and mdb databases and change the ROOTPW, import the schemas, change the domain, create a DIT and issue SSL certificates ALL of-course again reflecting your network and while ONLY using the OLC way with .ldif files.
The OUs People,Group and sudoers will be created together with a group "ldapusers" with gid=10000

3.KERBEROS KDC and KADMIN servers will configured,the db initialized to reflect YOUR realm and principals will be added for host/FQDN and nfs/FQDN together with their KEYS.

You will be prompted to give the passwords for the principals "root/admin"@REALM" and "root@REALM"

4.The NFS SERVER will ask you to choose a directory which it will then share with security sec=krb5p

5.A SAMBA SERVER will be installed and configured to share two directories.One open to guests and read-only and another "private" to be accessible only by a specific group.

6.Finally NTPd time synchronization daemon will be installed.

DIRECTORY CLIENT INSTALLATION SCRIPT

Here is a script that will turn a Gentoo machine into the Directory Servers Client.
It will first prompt you to enter the IP of the Server.
It DOES need ROOT SSH ACCESS TO THE SERVER WITH PASSWORD.
It will then:

Create ssh keys

Copy them to the Server

Probe the Server for the domain-name

Prompt the user to enter a <name> to use with the Server domain.

After thus configuring FQDN ...........

Copy the /etc/krb5.conf and /etc/openldap/ldap.conf FROM the Server TO the Client.

It will install openldap mit-krb5 sssd and pam_krb5 and nfs-utils with the appropriate USE flags

It will configure the right sssd.conf, nsswitch.conf and system-auth files to enable Network Authentication.

Finally it will create principals for host and nfs in Kerberos database and

Modify sshd_config to set "GSSAPIAuthentication yes" so as to enable ssh-ing locally as a remote user from the Server's Openldap DB.
