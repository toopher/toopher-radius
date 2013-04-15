How to set up a Toopher-Protected VPN on Azure in 57 easy steps
======================================================
*(or, why I worked for two weeks and only produced 30 lines of code)*

The goal of this walkthrough is to enabled the reader to set up a cloud-hosted VPN network, with logins optionally protected by Toopher 2-Factor authentication on a per-user basis.  This document uses the Microsoft Azure platform, but the instructions should be able to be adapted to other hosting services or physical machines without difficulty.  Before continuing, make sure you have an Azure account.  We will be setting up one Small VM and one Extra-Small VM, as well as one private network.  This is within the allowance for free usage with a BizSpark account.  At full price, it would probably cost about $70 monthly.

Setting up the Windows-based VPN
--------------------------------
We will be using Windows 2008 r2 for our VPN / Active Directory server.  Older versions will probably work as well with some changes to the steps.  I have adapted these instructions from a [great walkthrough video](http://youtu.be/QKSNDITI3pE) on YouTube.  That link is recommended viewing before completing this section.

Due to architectural limitations of Azure, only SSTP VPNs are possible.  This is slightly more complex than traditional IPSec VPNs, and has the disadvantage of being less compatible with non-windows clients (SSTP clients are available, but the "standard" VPN clients on OSX and Linux will not work).  If you are in an environment that allows creation of an IPSec VPN, you can set up the VPN on your own and then start using this walkthrough at the FreeRadius section (below).

### Required Roles
Your Windows Server needs the following roles installed:
4. Network Policy and Access Server

### Setup Active Directory
Install Active Directory Domain Services, create a domain (I created vpn.toopher.com), and promote the server to Domain Controller.  I found the Windows 2003 functional level to be adequate both for the Forest and Domain functional levels.  Install DNS when prompted.

### Generate a server certificate
Install the Active Directory Certificate Services role, and select the "Certification Authority" and "Certification Authority Web Enrollment" role services.  I set up a Standalone Root Certificate server - while this makes the process a bit easier, it also means that your clients by default will not trust the certificates and each client will need to manually import the root certificate in order to log in.  Sorry.  Create a new private key and complete the Add Roles Wizard using the defaults.
Open IIS Manager and create a temporary self-signed certificate.  Find the default site, and add a HTTPS binding using the self-signed certificate, then open a web browser and navigate to [the AD Certificate Services webpage](https://localhost/certsrv).
Use the Certificate Services page to request a new server certificate (Request a certificate -> Advanced Request -> Create and submit a request on this CA).  Enter your server name (vpn.toopher.com) and for Type, select "Server Authentication Certificate", and hit Submit.  This creates a pending certificate request that you must acknowledge in Server Manager.  Once you have issued the request through Server Manager, navigate back to [the CA page](https://localhost/certsrv), and click the "View the status of a pending certificate request" link.  Install the issued certificate.
By default, the certificate gets issued under the user account, but it needs to be moved to the Computer account so it is available for IIS.  To do this, launch Microsoft Management Console (start -> run-> "mmc.exe").  In File -> Add/Remove Snap-In, add two copies of the Certificates snap-in - one for the user account, and one for the local computer account.  Click OK, then move the new certificate from its default location at Current User -> Personal to Local Computer -> Personal.
Once you have moved the certificate, go back to IIS Manager and set the site to use the new certificate issued by the CA.


### Set up a simple VPN
Install the Network Policy and Access Server role, and select the "Network Policy Server" and "Routing and Remote Access Services" roles, along with the associated sub-roles.
Configure Routing and Remote Access in Server Manager (right-click [Roles -> Network Policy and Access Services -> Routing and Remote Access] and select 'Configure...').  Select "Custom Configuration", and in the next screen choose "VPN Access" and "NAT", then complete the wizard.
Set the SSTP Server Certificate to match IIS: Right-click RRAS and select properties.  In the dialog, under the "Security" tab in "SSL Certificate Binding", select the same certificate that you set for IIS.
Choose an IP address pool to assign to the clients:  In the IPv4 tab, select "Static address pool", and create a pool of addresses.  I created a range from 192.168.200.100 - 192.168.200.199, allowing up to 99 simultaneously connected clients (one IP is used by the RRAS server).
Set up NAT - this allows VPN-connected clients to connect to the internet using the VPN server's connection.  Right-click the NAT node (RRAS->IPv4->NAT), and select New Interface.  Choose the interface that handles internet traffic (on Azure, this will be your virtual network connection, which is confusing), and in the next screen, mark it as a "Public interface connected to the Internet" and select "Enable NAT on this interface".

### Create an Active Directory user
Open the Active Directory Users and Computers manager, and create a new user/password.  Uncheck the "User must change password..." box, and select OK.


### IMPORTANT!  Manually import the CA certificate
Since we created our own Root CA, the CA certificate must be manually installed on any clients that will connect to the VPN server.  From a web browser on the client, browse to https://your.vpn.server/certcarc.asp (obviously, replace your.vpn.server with the actual domain name of your VPN server).  Click the first link ("To trust certificates issued from this certificate authority...").
As with the initial certificate that we requested for the VPN server, this certificate must be manually moved from the "Current User" account to "Local Computer".  Open MMC as before with two instances of the Certificates snap-in, and move the certificate from Current User -> Trusted Root Certification Authorities to Local Computer -> Trusted Root Certification Authorities.

At this point, you should be able to set up a SSTP VPN connection from a windows-based client.

Set up the FreeRADIUS server
----------------------------

FreeRADIUS runs on many platforms, including Windows (using CygWin).  In this example, I am going to use Ubuntu Server 12.04 LTS.

Before you start:

    sudo apt-get update
    sudo apt-get upgrade
    sudo apt-get install build-essential

### Install FreeRADIUS and required perl modules

    sudo apt-get install freeradius

apt-get will have automatically started freeradius.  Stop it so we can finish getting it set up.

    sudo service freeradius stop

Get a copy of the toopher freeradius configuration files from bitbucket.  Assuming you have checked out the toopher repository under ~/toopher:

    sudo cp -r ~/toopher/toopher-vpn/freeradius/etc/raddb/* /etc/freeradius/
    sudo apt-get install libnet-ssleay-perl
    sudo cpan JSON
