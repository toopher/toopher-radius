
Building Debian Packages for FreeRadius
---------------------------------------

First, checkout out the proper FreeRADIUS branch for the Toopher-RADIUS distribution:

* Toopher-RADIUS 1.0 -> FreeRADIUS branch `v2.x.x`, commit `077a3739`

Install the `dpkg-dev` package via apt-get if necessary

Install the FreeRADIUS build dependencies:

    sudo apt-get build-dep freeradius

Finally, build the .deb packages:

    # from the FreeRADIUS source directory
    fakeroot dpkg-buildpackage -b -uc


Building RPMS for Centos (or other RedHat)
------------------------------------------

These instructions are adapted from the FreeRADIUS wiki page at http://wiki.freeradius.org/guide/Red-Hat-FAQ

Download the Fedora source RPM for FreeRADIUS 2.2.3: 

    wget http://kojipkgs.fedoraproject.org//packages/freeradius/2.2.3/6.fc19/src/freeradius-2.2.3-6.fc19.src.rpm

Install rpm-build and yum-utils

    sudo yum install rpm-build yum-utils

Install the SRPM

    rpm -ihv freeradius-2.2.3-6.fc19.src.rpm

Unfortunatlely, yum-builddep sucks, so the build dependencies must be installed manually:

    sudo yum install autoconf libtool libtool-ltdl-devel openssl-devel pam-devel \
        zlib-devel net-snmp-devel net-snmp-utils readline-devel libpcap-devel \
        systemd-units openldap-devel krb5-devel perl-ExtUtils-Embed python-devel \
        mysql-devel postgresql-devel unixODBC-devel systemd-units
