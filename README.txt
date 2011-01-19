DESCRIPTION
-----------
WindowsLiveID module for Drupal will allow Drupal sites to have authentication using Windows Live.
A Windows Live account needs to have an associated user account in Drupal to be able to login.

INSTALLATION
------------
Prerequisites:
1) Drupal7 installed and running
2) MySql 5.1 or above
3) php 5.2.0 or above

Installation Instructions:
1. Download WindowsLiveID module for Drupal
2. Copy Module files
   -Create Module Directory <Drupal-install-Root-dir>/sites/all/modules/windowslive
   -copy module files to <Drupal-install-Root-dir>/sites/all/modules/windowslive
<Drupal-install-Root-dir> is the Drupal installation directory on the machine. Ex: C:\www\Drupal7

3. Register the Windows Live Application in Windows Live Application Management Site
   - Go to Windows Live Application Management Site (http://go.microsoft.com/fwlink/?LinkID=144070) from browser. 
   - Signin with Windows Live ID. If you don't have one, then create a new Windows Live ID for this application.
   - Add a web application with domain name. Keep a note of ClientId/AppId and SecretKey of this application.
   - Provide additional settings for ‘Return URL’ by clicking on 'Essentials' link below the Client ID and Secret Key. Set 
     the ‘Return URL’ for your application in Windows Live Application Management Site to ‘webauth-handler.php’
     e.g. If you are manually extracting module to <Drupal-install-Root-dir>/sites/all/modules/windowslive folder, then
     this URL should be <DrupalRootUrl>/sites/all/modules/windowslive/webauth-handler.php

     But if you are directly uploading the tarball/zipball from github repository using Drupal UI, then the URL 
     should be <DrupalRootUrl>/sites/all/modules/<TarZipballFileNameWithoutExtension>/webauth-handler.php

<DrupalRootUrl> is the root http URL of Drupal installation. Ex: http://myhostname/Drupal7
<TarZipballFileNameWithoutExtension> is the file name of your github tarball/zipball without extension. 
e.g. When you download tarball/zipball from github, gutgub generates file name like 
schakra-WindowsLiveID-Drupal-Module-428f9e3.zip and TarZipballFileNameWithoutExtension will be 
schakra-WindowsLiveID-Drupal-Module-428f9e3

4. Enable and configure WindowsLiveID Module in Drupal.
  - Login to Drupal as Admin.
  - Enable the WindowsLiveID module from modules section and save the configuration.
  - Set the values for Client ID and Secret Key for WindowsLiveID module in 'Configure' option.
  Verify WindowsLiveID Module login link will be enabled in the login screen of Drupal.

USAGE
-----
1)User Login  
    - Clicking on ‘Log in using Windows Live ID’ link will take the user to Windows Live authentication page if user not logged in yet.
    - After the user logins successfully on the Windows Live page, the Windows Live Service will automatically redirect the user back to the Drupal web site.
    - User can login and associate the Windows Live ID, if they have a Drupal account before.
    - User can register and login with the Windows Live ID, once the site administrator approves the request and user validates Drupal account.
2) Administering WindowsLiveId Module
    - In addition to managing the Installation settings the Administer can,
    - From the User Account page Remove existing identities (Association with Windows Live ID)

LIMITATIONS AND KNOWN ISSUES
----------------------------
1. During Logout, user is not logged out from Windows Live ID sites. So the user is expected to close the browser session to remove any Windows Live cookies or tokens 
   in the current browser session.