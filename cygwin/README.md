Building Toopher-Freeradius for CYGWIN
======================================

Validated for Cygwin 1.7.34 (32-bit), perl 5.12.3, Freeradius 2.2.0

Setup
-----

### Installing Cygwin
1. Download and install Cygwin (must be 32-bit) from https://cygwin.com
2. Add the following packages to your Cygwin distribution:

        make
        wget
        git
        gcc-core
        openssl-devel
        openldap-devel
        gcc-g++
        libgdbm-devel

3. If you have whitespace in your home directory, edit `/etc/passwd` to change your home directory

    How to create `/etc/passwd`, if it does not exist:

        mkpasswd -L > /etc/passwd

### Installing WiX Toolset
1. Download and install WiX Toolset from http://wixtoolset.org
2. Add the directory `C:\Program Files (x86)\WiX Toolset v3.9\bin` to your PATH

  Windows: My Computer -> Properties -> Advanced system settings -> Environment Variables...

### Building the Installer
1. Create and upload an SSH public key for your VM to BitBucket, so the build script can download the FreeRadius source

        ssh-keygen
        cat ~/.ssh/id_rsa.pub

2. Run `./build` in a Cygwin terminal
3. Run `build-installer.cmd` in Windows Command Prompt

### Troubleshooting Build Errors
#### CPAN module failing to install
If you see a large number of failures to install a CPAN module or a CPAN module is taking too long to install, try installing the module with staticperl for a more verbose output:

    ./staticperl instcpan Net::SSLeay

#### Perl syntax/function errors
If the build output contains errors regarding Perl syntax or incorrect function calls, make sure that you are using the perl that was built with staticperl in `.staticperl/bin`

#### Missing cyggcc_s-1.dll
If you are missing `/bin/cyggcc_s-1.dll`, make sure that you are running a 32-bit version of Cygwin

### TODO
CPAN module `Time::HiRes` fails to install via staticperl -- this prevents Windows users from using the `pap_challenge_request.pl` script for debugging.
