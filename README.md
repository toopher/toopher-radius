Toopher-RADIUS version 1.4
======================================

Toopher uses the popular open-source [FreeRadius server](http://freeradius.org/) as the base for its RADIUS solution.

Installation Requirements
-------------------------
* Windows Server 2008, Ubuntu Server 12.04 LTS, CentOS/RHEL 6.4 64-bit : Other Windows OS versions are likely to work without issue.  For Linux environments, only those listed have been tested.
* Internet Connectivity: The Toopher-RADIUS Server must be able to contact the [Toopher Web API](https://api.toopher.com/).  Administrators should add appropriate firewall exceptions as necessary.
* RADIUS-Compatible Gateway Device: The user-facing device or service that is used with the Toopher-RADIUS server must support the RADIUS `Access-Challenge` packet type, allowing the Toopher-RADIUS server to request additional data from the user (for instance, when pairing a new mobile device).  Almost all commercial VPN products satisfy this requirement, although exceptions do exist (most notably the Microsoft RRAS service)


Installing and Configuring the Toopher RADIUS server
======================================================

Set Up LDAP Integration
-----------------------
Integrating Toopher into your organization's LDAP schema provides a simple way to administer per-user Toopher settings,
and is the recommended deployment method. 

### Prepare the Active Directory / LDAP Server for Toopher Administration
On the LDAP server, create a group called `ToopherUsers`

In addition, if your LDAP server is not configured to allow anonymous search, you should create a user LDAP account that has `search` permission for the `sAMAccountName` attribute (if using Active Directory), or `uid` (for most other LDAP schemas).


Installing the RADIUS Server
-----------------------------
### Installing on CentOS / RHEL
The included `install-centos.sh` script takes care of the full installation process:

    cd linux && sudo ./install-centos.sh

### Installing on Ubuntu (or other debian-based distro)
ensure that the OS is updated, the `build-essential` package is installed, and `CPAN` in up-to-date:

    sudo apt-get update
    sudo apt-get upgrade
    sudo apt-get install build-essential
    sudo cpan CPAN

run the provided install-ubuntu.sh script as root:

    cd linux && sudo ./install-ubuntu.sh

If the installation script stalls on a CPAN step, you may need to update the CPAN mirror list in the cpan shell:

    sudo cpan
    cpan> o conf init urllist
    cpan> o conf commit
    cpan> exit

Ubuntu installs the FreeRADIUS configuration files to `/etc/freeradius` instead of `/etc/raddb`.  Where this document references files under `/etc/raddb`, please edit the corresponding file under `/etc/freeradius`.

### Installing on Windows
The included MSI package will install the Toopher-RADIUS server for windows, along with necessary configuration tools.

RADIUS Configuration
--------------------
### Linux Configuration
Add the IP address of your VPN solution to /etc/raddb/clients.conf.  This will vary according to your network environment.  As an example, to add a VPN client named `PA_VM` accessiable at local IP address of `172.16.42.201` with RADIUS secret `s3cr3t`, add the following four lines to `clients.conf`: 

    client PA_VM {
         ipaddr = 172.16.42.201
         secret = s3cr3t
    }


Before you can run the server, you need to edit /etc/raddb/toopher_radius_config.pm to suit your site.

    my $toopher_config =
    {
      toopher_api => {
        url   =>  'https://api.toopher.com.com/v1/',
        key   =>  'YOUR TOOPHER API KEY',
        secret=>  'YOUR TOOPHER API SECRET',
        poll_timeout => 30,  # number of seconds before the server gives up on mobile authentication and asks for OTP
        },
      prompts => {
        pairing_challenge => 'Toopher 2-factor authentication is enabled for your account.  Please enter the pairing phrase generated by the Toopher mobile app:',
        otp_challenge => 'Timeout while contacting the Toopher API.  Please enter the OTP generated by the Toopher Mobile App to proceed.',
        self_reset => 'If you have lost your mobile device and need to recover your pairing, enter the word "reset"',
        name_terminal_challenge => 'To enable Toopher Automation, please enter a name for this terminal (e.g. "Home Laptop" or "Office PC")',
        reset_link_set => 'An email has been sent to %email% with a link to reset the Toopher pairing associated with this account',
        }
    };

At a minimum, you must change the "key" and "secret" values in the
toopher_api section.  You can generate new requester credentials at the 
[Toopher Developer Site](https://dev.toopher.com).

Additionally, edit /etc/raddb/modules/ldap to point to your LDAP / Active Directory server

    conf
      ldap {
        server = "ldap.example.com"
        port = 389
        identity = "cn=Radius Admin,cn=users,DC=example,DC=com"
        password = p@ssw0rd
        basedn = "cn=users,DC=example,DC=toopher,DC=com"
        filter = "(|(uid=%{%{Stripped-User-Name}:-%{User-Name}})(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}}))"
        groupname_attribute = cn
        groupmembership_filter = "(|(&(objectClass=GroupOfNames)(member=%{control:Ldap-UserDn}))(&(objectClass=GroupOfUniqueNames)(uniquemember=%{control:Ldap-UserDn}))(&(objectClass=group)(member=%{control:Ldap-UserDn})))"

        # LOTS OF OTHER SETTINGS
    }

Most users will only need to edit the `server`, `identity`, `password`, and `basedn` settings.  `identity` and `password` correspond to an LDAP account that is allowed `search`/`read` access to `User` objects.  If your LDAP server permits anonymous searches, you can comment out these two lines.

The default filters should work for Active Directory, as well as any LDAP server using the [RFC 2798 (inetOrgPerson)](http://tools.ietf.org/html/rfc2798) schema.

Additionally, you may customize the prompt displayed to users when they initially pair their device with Toopher.  The maximum length of this prompt is 253 characters due to technical limitations of the RADIUS specification.
 
### Windows Configuration
Windows Administrators can configure the most commonly-used parameters through the Start menu (Toopher -> Toopher-RADIUS Server -> Configuration)

There are three general parameter categories in the Windows installation:

Toopher API Settings:

* `TOOPHER_API_KEY`, `TOOPHER_API_SECRET` : These credentials are used to securely identify your server to the Toopher Web API.  New credentials can be generated by creating an account at [https://dev.toopher.com]
* `TOOPHER_POLL_TIMEOUT` : Maximum amount of time that Toopher will attempt to authenticate the user through the Toopher smartphone app before failing over to OTP validation.
* `TOOPHER_API_URL` : This should stay at the default setting of [https://api.toopher.com/v1/](https://api.toopher.com/v1/).

RADIUS Prompt Text:

* `PROMPT_PAIRING_CHALLENGE` : Text displayed to the user when they first pair a mobile device with their account.
* `PROMPT_OTP_CHALLENGE` : Text displayed to the user when they need to validate with a One-Time Password (for instance, if their mobile device does not have internet access)

LDAP settings you will need to edit:

* `LDAP_BASEDN` : Base DN to use for username searches
* `LDAP_HOST` : Hostname or IP Address of LDAP or ActiveDirectory server
* `LDAP_IDENTITY` : DN of user to use when connecting to LDAP server to perform user searches.
* `LDAP_PASSWORD` : The password corresponding to the `LDAP_IDENTITY` user.  *this password will be stored in plaintext on the RADIUS server*

LDAP Settings you probably don't need to edit: The following LDAP settings only need to be edited if your organization uses a non-standard LDAP schema.  The default values 
should work for ActiveDirectory and [inetOrgPerson](http://tools.ietf.org/html/rfc2798) schema, which account for the vast majority of LDAP user databases.  If your organization needs help integrating Toopher-RADIUS with a different LDAP schema, please contact [support@toopher.com](mailto:support@toopher.com) for assistance.

* `LDAP_GROUP_MEMBERSHIP_FILTER`
* `LDAP_SEARCH_FILTER`


Start the RADIUS server
-----------------------
### Ubuntu
    sudo service freeradius start

### CentOS / RHEL
    sudo service radiusd start

### Windows
    net start toopher-freeradius


Configure your RADIUS-Compatible Gateway Device
----------------------------------------------------
Follow vendor instructions for your RADIUS-Compatible VPN (or other gateway device) to connect it to the Toopher-RADIUS server.  In addition to entering the IP address and shared secret for the Toopher-RADIUS server, the RADIUS timeout will typically need to be increased well above the default.  This timeout should be set slightly higher than the `poll_timeout` setting configured in `toopher_radius_config.pm`, above.  While the Toopher-RADIUS server will authenticate most requests within a few seconds, requests which require the user to respond to a prompt on their device will take considerably longer.

Add Toopher Protection to Individual Users
------------------------------------------

Toopher is enabled/disabled for an individual user by adding or removing that user from the `ToopherUsers` LDAP group.  Users who are members of `ToopherUsers` will be subject to an additional Toopher Authentication step before being allowed access via RADIUS.

Resetting a User's Pairing
-----------------------------------
Resetting a pairing is occasionally necessary, for instance if a user gets a new mobile device and wants to stop authenticating with their old device.  

### Self-Reset Methods
The easiest way for users to reset their pairing is by deleting the existing pairing from their mobile device.  In the Toopher Mobile App, select the pairing on the main screen, then press "Remove Pairing".  The user will be prompted to re-pair with a new mobile device the next time they authenticate with the Toopher-RADIUS server.

Of course, if a user needs to reset their pairing, it likely means they do not have access to their mobile device.  In this case, users can reset their pairing by waiting for the Toopher OTP prompt, then typing the word "reset" instead of the One-Time Password.  The Toopher API will then send a reset link to the user's email address (defined in LDAP).

### Administrative Reset
In some cases, a user may require administrator assistance to recover a lost pairing.  This most commonly happens if the user loses their mobile device, or uninstalls the Toopher app without first deleting their pairing.  There are two options for restoring access to the user:

* Remove the user from the `ToopherUsers` LDAP group - This will preserve the Pairing informaion in the Toopher API server, while allowing the user to bypass Toopher authentication to log in.  This method can be effectively undone by adding the user back to the `ToopherUsers` group.
* Reset the user's pairing - Administrators can reset a user's pairing information by running `perl /etc/freeradius/toopher_radius.pl reset-pairing [username]` on the Toopher-RADIUS server.  This command will remove that user's pairing information from the Toopher API, and they will be prompted to re-pair the next time they authenticate.  Windows users can access this tool through the Start menu (Toopher -> Toopher-RADIUS Server -> Reset User Pairing)

Troubleshooting
---------------------

## SELinux Issues

* Symptom: RADIUS returns error messages like `Unknown error while authenticating: 500 Can't connect to toopher-api.appspot.com:443` when run as a service, but not when run in debug mode.
* Possible Cause: The SELinux default `radius` module settings does not permit the server to access the Toopher API to complete authentication
* Fix: Create a `toopher_radius` policy module to allow the blocked connection attempts:

    grep radiusd /var/log/audit/audit.log | audit2allow -M toopher_radius
    semodule -i toopher_radius.pp



Support Information
---------------------
Please do not hesitate to contact [support@toopher.com](mailto:support@toopher.com) with any questions or concerns.

Changelog
---------
v1.4
* Add support for self-service pairing reset

v1.3

* Add support for Feature Phone (SMS-based) pairings

v1.2.1

* Add CentOS/RHEL installer

v1.2

* Add support for naming user terminals and enabling automation

v1.1

* Add Windows Installer

v1.0

* Remove local storage requirements
* Support LDAP/ActiveDirectory integration without requiring schema changes
