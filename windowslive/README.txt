DESCRIPTION
-----------
Active Directory module for Drupal 7 will allow Drupal sites to have Single Sign On
authentication using an ADFS 2.0 enabled server using the WS Federation
Protocol.  Existing or new user accounts can be associated with an Active Directory logon
identity.

INSTALLATION
------------
Prerequisites:
1) Drupal7 installed and running
2) PHP 5.2 or above (also required by Drupal7).
3) Access to an ADFS 2.0 server that can be configured for this site.

Installation Instructions:
1) Download the Active Directory module for Drupal (ADFS directory).
2) Copy the module files
    - Move the ADFS folder to <Drupal-install-Root-dir>/sites/all/modules
3) Login to Drupal 7 as a site administrator
4) Under Modules, activate the Active Directory module and Save Configuration
5) Select Permissions, next to Active Directory module and enable Administrator and Save
6) Select Configuration->System->ADFS Settings
    a. Enter the Active Directory Federation Service URL provided by your ADFS IdP SSO provider.
    b. Enter the identity of your Drupal site (i.e. urn:federation:mysitedomainname)
    c. (Optional) Enter a private certificate Path and certificate password if used
       to decrypt authentication responses which have been sent encrypted. The certificate
	format supported is '.pem'.    
    d. Save the Settings


CONFIGURATION
-------------
Configuring ADFS 2.0 (On Windows Server 2008):
1) Open the ADFS 2.0 Manager
2) Right click Relying Party Trust and select Add Relying Party Trust
3) Start the Wizard:
    a. Select Data Source: Select Manual Configuration
    b. Specify Display Name: Enter an identity for your Drupal site (same as
       6.b under Installation)
    c. Choose Profile: Select SAML 2.0
    d. Configure Certificate: Only set this if you want Encrypted responses (as
       in 6.d under Installation)
    e. Configure URL: Select WS-Federation Passive and enter the path to the
       ADFS modules entry point: <Drupal-Site-URL>/?q=adfs/prp
    f. Configure Identifier: Add the identity form 6.b under Installation
    g. Choose Issuance Authorization Rules: This setting is determined by the
       system administrator, use Permit All to allow any user access to the
       Drupal site, otherwise configure access individually
    h. Ready to Add Trust: Close the Wizard and continue with Claims
    i. Configure Claims:  This may vary based on configuration and determines
       the values for 6.e under Installation.
        - A sample configuration with mandatory claim "Name ID" is as below
             - Use LDAP Attributes
             - Name the claim: Default
             - Attribute Store: Active Directory
             - LDAP: SAM-Account-Name    Outgoing: Name ID

USAGE
-----
1) User Login
    - Clicking on this "Sign in with ADFS" link will redirect the user to the
      authentication server where they enter their ADFS credentials
    - For new users, you will be prompted to create a new account and the
      information returned by the ADFS server will pre-populate the account
      form
    - For existing users you will be directed to log in first and then use the
      ADFS Identity management page to add your credentials.
    - After first login, the user will be authenticated normally and taken into
      their site account
2) Using ADFS Identity Manager
    - Go to account settings
    - Select the ADFS Identity page
    - To Add an ADFS account, select Add ADFS button and log in with your
      ADFS credentials when prompted.
    - To Remove an ADFS account, select the delete link to the right of the
      ADFS identity listed
3) Administering Active Directory Module
    - In addition to managing the Installation settings the Administer can,
    - From the User Account page Remove existing identities
