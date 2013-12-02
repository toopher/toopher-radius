
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
