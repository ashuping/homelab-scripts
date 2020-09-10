# Function
Watcher Oran helps to propagate LDAP group membership to subgroups.

Groups in the LDAP directory may have a custom "supergroup" attribute, pointing
to one or more supergroups. This script uses those attributes to construct a
tree of groups. Then, it propagates users down the tree.

So, if there is a group structure like this

    == ou=default
       |
       +=== cn=netAdmins (group)
       |
       +=== ou=bobWorkstation
       |    |
       |    +=== cn=bobAdmins (group, supergroup=netAdmins)
       |
       +=== ou=sandraServer
            |
            +=== cn=sandraAdmins (group, supergroup=netAdmins)

Then this script will ensure that any users that are members of `netAdmins` are
also members of `bobAdmins` and `sandraAdmins` - but *not* the other way around!

This makes it easier to configure individual servers (e.g. admin access to
bobWorkstation can be restricted to only `bobAdmins`, and any `netAdmins` would
still automatically get access).

# Prerequisites
This script requires these python modules:

* coloredlogs
* python-ldap

**python-ldap**, also requires some C headers. These can be found in (`ubuntu package`/`centos7 package`):

* `libldap2-dev` / `openldap-devel`
* `libsasl2-dev` / `cyrus-sasl-devel`
* `libssl-dev` / `openssl-devel`
* `python-dev` / `python3-devel`
