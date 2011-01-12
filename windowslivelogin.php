<?php

/**
 * FILE:        windowslivelogin.php
 *
 * DESCRIPTION: Sample implementation of Web Authentication protocol in PHP.
 *              Also includes trusted login and application verification
 *              sample implementations.
 *
 * VERSION:     1.0
 *
 * Copyright (c) 2007 Microsoft Corporation.  All Rights Reserved.
 */

/**
 * Holds the user information after a successful login.
 */
class WLL_User
{
    public function __construct($timestamp, $id, $flags, $context, $token)
    {
        self::setTimestamp($timestamp);
        self::setId($id);
        self::setFlags($flags);
        self::setContext($context);
        self::setToken($token);
    }

    private $_timestamp;
    
    /**
     * Returns the Unix timestamp as obtained from the SSO token.
     */
    public function getTimestamp()
    {
        return $this->_timestamp;
    }

    private function setTimestamp($timestamp)
    {
        if (!$timestamp) {
            throw new Exception('Error: WLL_User: Null timestamp.');
        }

        if (!preg_match('/^\d+$/', $timestamp) || ($timestamp <= 0)) {
            throw new Exception('Error: WLL_User: Invalid timestamp: ' 
                                . $timestamp);
        }
        
        $this->_timestamp = $timestamp;
    }

    private $_id;

    /**
     * Returns the pairwise unique ID for the user.
     */
    public function getId()
    {
        return $this->_id;
    }

    private function setId($id)
    {
        if (!$id) {
            throw new Exception('Error: WLL_User: Null id.');
        }

        if (!preg_match('/^\w+$/', $id)) {
            throw new Exception('Error: WLL_User: Invalid id: ' . $id);
        }
        
        $this->_id = $id;
    }

    private $_usePersistentCookie;

    /**
     * Indicates whether the application is expected to store the
     * user token in a session or persistent cookie.
     */
    public function usePersistentCookie() 
    {
        return $this->_usePersistentCookie;
    }

    private function setFlags($flags)
    {
        $this->_usePersistentCookie = false;
		if (preg_match('/^\d+$/', $flags)) {
            $this->_usePersistentCookie = (($flags % 2) == 1);
        }
    }

    private $_context;
    
    /** 
     * Returns the application context that was originally passed
     * to the login request, if any.
     */
    public function getContext()
    {
        return $this->_context;
    }

    private function setContext($context)
    {
        $this->_context = $context;
    }

    private $_token;

    /**
     * Returns the encrypted Web Authentication token containing 
     * the UID. This can be cached in a cookie and the UID can be
     * retrieved by calling the ProcessToken method.
     */
    public function getToken()
    {
        return $this->_token;
    }

    private function setToken($token)
    {
        $this->_token = $token;
    }
}

class WindowsLiveLogin
{
    /* Implementation of basic methods for Web Authentication support. */

    private $_debug = false;

    /**
     * Stub implementation for logging errors. If you want to enable
     * debugging output, set this to true. In this implementation
     * errors will be logged using the PHP error_log function.
     */
    public function setDebug($debug)
    {
        $this->_debug = $debug;
    }

    /**
     * Stub implementation for logging errors. By default, this
     * function does nothing if the debug flag has not been set with
     * setDebug. Otherwise, errors are logged using the PHP error_log
     * function.
     */
    private function debug($string)
    {
        if($this->_debug) {
            error_log($string);
        }
    }
    
    /**
     * Stub implementation for handling a fatal error.
     */
    private function fatal($string)
    {
        self::debug($string);
        throw new Exception($string);
    }
    
    /**
     * Initialize the WindowsLiveLogin module with the application ID,
     * secret key and security algorithm.
     *
     * We recommend that you employ strong measures to protect the
     * secret key. The secret key should never be exposed to the
     * Web or other users.
     *
     * Be aware that if you do not supply these settings at
     * initialization time, you may need to set the application ID,
     * secret key and security algorithm using the appropriate setters.
     */
    public function __construct($appid=null, $secret=null, $securityalgorithm=null)
    {
        if ($appid) {
            self::setAppId($appid);
        }
        if ($secret) {
            self::setSecret($secret);
        }
        if ($securityalgorithm) {
            self::setSecurityAlgorithm($securityalgorithm);
        }
    }

    /**
     * Initialize the WindowsLiveLogin module from a settings file. 
     * 
     * 'settingsFile' specifies the location of the XML settings file
     * containing the application ID, secret key, and an optional 
     * security algorithm. The file is of the following format:
     * 
     * <windowslivelogin>
     *   <appid>APPID</appid>
     *   <secret>SECRET</secret>
     *   <securityalgorithm>wsignin1.0</securityalgorithm>
     * </windowslivelogin>
     *
     * We recommend that you store the Windows Live Login settings
     * file in an area on your server that cannot be accessed through
     * the Internet. This file contains important confidential
     * information.
     */
    public static function initFromXml($settingsFile)
    {
        $o = new WindowsLiveLogin();
        $settings = $o->parseSettings($settingsFile);
        $o->setAppId(@$settings['appid']);
        $o->setSecret(@$settings['secret']);
        $o->setSecurityAlgorithm(@$settings['securityalgorithm']);
        $o->setBaseUrl(@$settings['baseurl']);
        $o->setSecureUrl(@$settings['secureurl']);
        $o->setDebug(@$settings['debug']);
        return $o;
    }

    private $_appid;

    /**
     * Use this method to set your application ID if you did not provide
     * one at initialization time.
     **/
    public function setAppId($appid)
    {
        if (!$appid) {
            self::fatal('Error: setAppId: Null application ID.');
        }
        if (!preg_match('/^\w+$/', $appid)) {
            self::fatal("Error: setAppId: Application ID must be alpha-numeric: $appid");
        }
        $this->_appid = $appid;
    }

    /**
     * Returns the application ID.
     */
    public function getAppId()
    {
        if (!$this->_appid) {
            self::fatal('Error: getAppId: Application ID was not set. Aborting.');
        }
        return $this->_appid;
    }

    private $_signkey;
    private $_cryptkey;
    
    /**
     * You can use this method to set your secret key if one
     * was not provided at initialization time.
     */
    public function setSecret($secret)
    {
        if (!$secret || (strlen($secret) < 16)) {
            self::fatal("Error: setSecret: Secret key is expected to be non-null and longer than 16 characters.");
        }
        
        $this->_signkey  = self::derive($secret, "SIGNATURE");
        $this->_cryptkey = self::derive($secret, "ENCRYPTION");
    }

    private $_securityalgorithm;

    /**
     * Set the version of the security algorithm being used.
     */
    public function setSecurityAlgorithm($securityalgorithm)
    {
        $this->_securityalgorithm = $securityalgorithm;
    }

    /**
     * Get the version of the security algorithm being used.
     */
    public function getSecurityAlgorithm()
    {
        $securityalgorithm = $this->_securityalgorithm;
        if (!$securityalgorithm) {
            return 'wsignin1.0';
        }
        return $securityalgorithm;
    }

    private $_baseurl;

    /**
     * Set the base URL to use for the Windows Live Login server. You
     * should not have to change this. Furthermore, we recommend that
     * you use the Sign In control instead of the URL methods
     * provided here.
     */
    public function setBaseUrl($baseurl) 
    {
        $this->_baseurl = $baseurl;
    }

    /**
     * Get the base URL to use for the Windows Live Login server. You
     * should not have to use this. Furthermore, we recommend that
     * you use the Sign In control instead of the URL methods 
     * provided here.
     */
    public function getBaseUrl() 
    {
        $baseurl = $this->_baseurl;
        if (!$baseurl) {
            return "http://login.live.com/";
        }
        return $baseurl;
    }

    private $_secureurl;

    /**
     * Set the secure (HTTPS) URL to use for the Windows Live Login server.
     * You should not have to change this.
     */
    public function setSecureUrl($secureurl) 
    {
        $this->_secureurl = $secureurl;
    }

    /**
     * Get the secure (HTTPS) URL to use for the Windows Live Login server.
     * You should not have to use this.
     */
    public function getSecureUrl() 
    {
        $secureurl = $this->_secureurl;
        if (!$secureurl) {
            return "https://login.live.com/";
        }
        return $secureurl;
    }

    /**
     * Processes the login response from Windows Live Login.
     * 
     * @param query contains the preprocessed POST query, a map of
     *              Strings to an an array of Strings, such as that 
     *              returned by ServletRequest.getParameterMap().
     * @return      a User object on successful login; otherwise null.
     */
    public function processLogin($query)
    {        
        $action = @$query['action'];
        if ($action != 'login') {
            self::debug("Warning: processLogin: query action ignored: $action");
            return;
        }
        $token  = @$query['stoken'];
        $context = urldecode(@$query['appctx']);
        return self::processToken($token, $context);
    }

    /**
     * Returns the sign-in URL to use for Windows Live Login. We
     * recommend that you use the Sign In control instead.
     *
     * @param context If you specify it, context will be returned
     *                as-is in the login response for site-specific 
     *                use.
     */
    public function getLoginUrl($context=null)
    {
        $url  = self::getBaseUrl(); 
        $url .= 'wlogin.srf?appid=' . self::getAppId();
        $url .= '&alg=' . self::getSecurityAlgorithm();
        $url .= ($context ? '&appctx=' . urlencode($context) : '');
        return $url;
    }
    
    /**
     * Returns the sign-out URL to use for Windows Live Login. We
     * recommend that you use the Sign In control instead.
     */
    public function getLogoutUrl()
    {
        return self::getBaseUrl() . "logout.srf?appid=" . self::getAppId();
    }

    /**
     * Decodes and validates a Web Authentication token. Returns a User
     * object on success. If a context is passed in, it will be
     * returned as the context field in the User object.
     */
    public function processToken($token, $context=null)
    {
        if (!$token) {
            self::debug('Error: processToken: Invalid token specified.');
            return;
        }

        $decodedToken = self::decodeToken($token);
        if (!$decodedToken) {
            self::debug("Error: processToken: Failed to decode token: $token");
            return;
        }

        $decodedToken = self::validateToken($decodedToken);
        if (!$decodedToken) {
            self::debug("Error: processToken: Failed to validate token: $token");
            return;
        }

        $parsedToken = self::parse($decodedToken);
        if (!$parsedToken) {
            self::debug("Error: processToken: Failed to parse token after decoding: $token");
            return;
        }
        
        $appid = self::getAppId();
        $tokenappid = @$parsedToken['appid'];
        if ($appid != $tokenappid) {
            self::debug("Error: processToken: Application ID in token did not match ours: $tokenappid, $appid");
            return;
        }

        $user = null;

        try {
            $user = new WLL_User(@$parsedToken['ts'], 
                                 @$parsedToken['uid'], 
                                 @$parsedToken['flags'], 
                                 $context, $token);
        } catch (Exception $e) {
            fatal::debug("Error: processToken: Contents of token considered invalid: " + $e->getMessage());
        }
        
        return $user;
    }
    
    /**
     * When a user signs out of Windows Live or a Windows Live
     * application, a best-effort attempt is made at signing out the
     * user from all other Windows Live applications the user might be
     * logged in to. This is done by calling the handler page for
     * each application with 'action' set to 'clearcookie' in the
     * query string. The application handler is then responsible for
     * clearing any cookies or data associated with the login. After
     * successfully logging out the user, the handler should return a
     * GIF (any GIF) as response to the action=clearcookie query.
     *
     * This function returns an appropriate content type and body
     * response that the application handler can return to signify a
     * successful sign-out from the application.
     */
    public function getClearCookieResponse()
    {
        $type = "image/gif";
        $content = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAEALAAAAAABAAEAAAIBTAA7";
        $content = base64_decode($content);
        return array($type, $content);
    }

    /**
     * Decode the given token. Returns null on failure.
     *
     * First, the string is URL unescaped and base64 decoded.
     * Second, the IV is extracted from the first 16 bytes the
     * string.
     * Finally, the string is decrypted by using the encryption
     * key.
     */
    public function decodeToken($token)
    {
        $cryptkey = $this->_cryptkey;
        if (!$cryptkey) {
            self::fatal("Error: decodeToken: Secret key was not set. Aborting.");
        }
        
        $ivLen = 16;
        $token = self::u64($token);
        $len = strlen($token);
        
        if (!$token || ($len <= $ivLen) || (($len % $ivLen) != 0)) {
            self::debug("Error: decodeToken: Attempted to decode invalid token.");
            return;
        }
        
        $iv      = substr($token, 0, 16);
        $crypted = substr($token, 16);
        $mode    = MCRYPT_MODE_CBC; 
        $enc     = MCRYPT_RIJNDAEL_128;
        return mcrypt_decrypt($enc, $cryptkey, $crypted, $mode, $iv);
    }

    /**
     * Creates a signature for the given string by using the signature
     * key.
     */
    public function signToken($token)
    {
        $signkey = $this->_signkey;
        if (!$signkey) {
            self::fatal("Error: signToken: Secret key was not set. Aborting.");
        }
        
        if (!$token) {
            self::debug("Attempted to sign null token.");
            return;
        }

        return hash_hmac("sha256", $token, $signkey, true);
    }

    /**
     * Extracts the signature from the token and validates it.
     */
    public function validateToken($token)
    {
        if (!$token) {
            self::debug("Error: validateToken: Invalid token.");
            return;
        }

        // PHP 5.3 doesn't support split - Use explode
		//$split = split("&sig=", $token);
		$explode = explode("&sig=", $token);
        //if (count($split) != 2) {
		if (count($explode) != 2) {
            self::debug("ERROR: validateToken: Invalid token: $token");
            return;
        }
        //list($body, $sig) = $split;
		list($body, $sig) = $explode;

        $sig = self::u64($sig);
        if (!$sig) {
            self::debug("Error: validateToken: Could not extract signature from token.");
            return;
        }

        $sig2 = self::signToken($body);
        if (!$sig2) {
            self::debug("Error: validateToken: Could not generate signature for the token.");
            return;
        }
        
          
        if ($sig == $sig2) {
            return $token;    
        }
        
        self::debug("Error: validateToken: Signature did not match.");
        return;
    }

    /* Implementation of the methods needed to do Windows Live
       application verification as well as trusted login. */

    /**
     * Generates an Application Verifier token. An IP address can be
     * included in the token.
     */
    public function getAppVerifier($ip=null)
    {
        $token  = 'appid=' . self::getAppId() . '&ts=' . self::getTimestamp();
        $token .= ($ip ? "&ip={$ip}" : '');
        $token .= '&sig=' . self::e64(self::signToken($token));
        return urlencode($token);
    }

    /**
     * Returns the URL needed to retrieve the application security
     * token.
     *
     * By default, the application security token will be generated
     * for the Windows Live site; a specific Site ID can optionally be
     * specified in 'siteid'. The IP address can also optionally be
     * included in 'ip'.
     * 
     * If 'js' is false, then JavaScript Output Notation (JSON) output 
     * is returned: 
     * 
     * {"token":"<value>"}
     * 
     * Otherwise, a JavaScript response is returned. It is assumed that
     * WLIDResultCallback is a custom function implemented to handle
     * the token value:
     * 
     * WLIDResultCallback("<tokenvalue>");
     */
    public function getAppLoginUrl($siteid=null, $ip=null, $js=null)
    {
        $url  = self::getSecureUrl();
        $url .= 'wapplogin.srf?app=' . self::getAppVerifier($ip);
        $url .= '&alg=' . self::getSecurityAlgorithm();
        $url .= ($siteid ? "&id=$siteid" : '');
        $url .= ($js ? '&js=1' : '');
        return $url;
    }

    /**
     * Retrieves the application security token for application
     * verification from the application login URL.
     *
     * By default, the application security token will be generated
     * for the Windows Live site; a specific Site ID can optionally be
     * specified in 'siteid'. The IP address can also optionally be
     * included in 'ip'.
     *
     * Implementation note: The application security token is
     * downloaded from the application login URL in JSON format
     * {"token":"<value>"}, so we need to extract <value> from
     * the string and return it as seen here.
     */
    public function getAppSecurityToken($siteid=null, $ip=null)
    {
        $body = self::fetch(self::getAppLoginUrl($siteid, $ip));
        if (!$body) {
            self::debug("Error: getAppSecurityToken: Could not fetch the application security token.");
        }
            
        preg_match('/\{"token":"(.*)"\}/', $body, $matches);
        if(count($matches) == 2) {
            return $matches[1];
        }
        else {
            self::debug("Error: getAppSecurityToken: Failed to extract token: $body");
            return;
        }
    }

    /**
     * Returns a string that can be passed to the GetTrustedParams
     * function as the 'retcode' parameter. If this is specified as
     * the 'retcode', then the app will be used as return URL after it
     * finishes trusted login.
     */
    public function getAppRetCode()
    {    
        return 'appid=' . self::getAppId();
    }

    /**
     * Returns a table of key-value pairs that must be posted to the
     * login URL for trusted login. Use HTTP POST to do this. Be
     * aware that the values in the table are neither URL nor HTML
     * escaped and may have to be escaped if you are inserting them in
     * code such as an HTML form.
     * 
     * User to be trusted on the local site is passed in as string
     * 'user'.
     * 
     * Optionally, 'retcode' specifies the resource to which
     * successful login is redirected, such as Windows Live Mail, and
     * is typically a string in the format 'id=2000'. If you pass in
     * the value from GetAppRetCode instead, login will be redirected
     * to the application. Otherwise, an HTTP 200 response is
     * returned.
     */
    public function getTrustedParams($user, $retcode=null)
    {
        $token  = self::getTrustedToken($user);
        if (!$token) {
            return;
        }
        $token = "<wst:RequestSecurityTokenResponse xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\"><wst:RequestedSecurityToken><wsse:BinarySecurityToken xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">$token</wsse:BinarySecurityToken></wst:RequestedSecurityToken><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"><wsa:Address>uri:WindowsLiveID</wsa:Address></wsa:EndpointReference></wsp:AppliesTo></wst:RequestSecurityTokenResponse>";
        
        $params = array();
        $params['wa']      = self::getSecurityAlgorithm();
        $params['wresult'] = $token;
        
        if ($retcode) {
            $params['wctx'] = $retcode;
        }
        
        return $params;        
    }

    /**
     * Returns the trusted login token in the format needed by the
     * trusted login gadget.
     *
     * User to be trusted on the local site is passed in as string
     * 'user'.
     */
    public function getTrustedToken($user)
    {
        if (!$user) {
            self::debug('Error: getTrustedToken: Null user specified.');
            return;
        }
        
        $token  = "appid=" . self::getAppId() . "&uid=" . urlencode($user) 
          . "&ts=". self::getTimestamp();
        $token .= "&sig="  . self::e64(self::signToken($token));
        return urlencode($token);
    }

    /**
     * Returns the trusted sign-in URL to use for Windows Live Login.
     */
    public function getTrustedLoginUrl()
    {
        return self::getSecureUrl() . 'wlogin.srf';
    }
    
    /**
     * Returns the trusted sign-out URL to use for Windows Live Login.
     */
    public function getTrustedLogoutUrl()
    {
        return self::getSecureUrl() . "logout.srf?appid=" + self::getAppId();
    }

    /* Helper methods */

    private function parseSettings($settingsFile)
    {
        $settings = array();
        $doc = new DOMDocument();
        if (!$doc->load($settingsFile)) {
            self::fatal("Error: parseSettings: Error while reading $settingsFile");
        }
        
        $appid = $doc->getElementsByTagName('appid');
        if($appid->length != 1) {
            self::fatal("error: parseSettings: Could not read application ID.");
        }
        $settings["appid"] = $appid->item(0)->nodeValue;

        $secret = $doc->getElementsByTagName('secret');
        if($secret->length != 1) {
            self::fatal("error: parseSettings: Could not read secret.");
        }
        $settings["secret"] = $secret->item(0)->nodeValue;

        $securityalgorithm = $doc->getElementsByTagName('securityalgorithm');
        if($securityalgorithm->length == 1) {
            $settings["securityalgorithm"] = 
              $securityalgorithm->item(0)->nodeValue;
        }

        $baseurl = $doc->getElementsByTagName('baseurl');
        if($baseurl->length == 1) {
            $settings["baseurl"] = $baseurl->item(0)->nodeValue;
        }

        $secureurl = $doc->getElementsByTagName('secureurl');
        if($secureurl->length == 1) {
            $settings["secureurl"] = $secureurl->item(0)->nodeValue;
        }

        $debug = $doc->getElementsByTagName('debug');
        if($debug->length == 1) {
            $settings["debug"] = $debug->item(0)->nodeValue;
        }

        return $settings;
    }
    
    /**
     * Derive the key, given the secret key and prefix as described in the
     * SDK documentation.
     */
    private function derive($secret, $prefix)
    {
        if (!$secret || !$prefix) {
            self::fatal("Error: derive: secret or prefix is null.");
        }        

        $keyLen = 16;
        $key = $prefix . $secret;
        $key = mhash(MHASH_SHA256, $key);
        if (!$key || (strlen($key) < $keyLen)) {
            self::debug("Error: derive: Unable to derive key.");
            return;
        }
        
        return substr($key, 0, $keyLen);
    }

    /**
     * Helper method to parse query string and return a table
     * representation of the key and value pairs.
     */
    private function parse($input)
    {                
        if (!$input) {
            self::debug("Error: parse: Null input.");
            return;
        }

        //$input = split('&', $input);
		$input = explode('&', $input);
        $pairs = array();
        
        foreach ($input as $pair) {
            //$kv = split('=', $pair);
			$kv = explode('=', $pair);
            if (count($kv) != 2) {
                self::debug("Error: parse: Bad input to parse: " . $pair);
                return;
            }
            $pairs[$kv[0]] = $kv[1];
        }
                
        return $pairs;
    }

    /**
     * Generates a timestamp suitable for the application verifier
     * token.
     */
    private function getTimestamp()
    {    
        return time();
    }

    /**
     * Base64-encode and URL-escape a string.
     */
    private function e64($input)
    {
        if (is_null($input)) {
            return;
        }
        return urlencode(base64_encode($input));
    }

    /**
     * URL-unescape and Base64-decode a string.
     */
    private function u64($input)
    {
        if(is_null($input))
            return;
        return base64_decode(urldecode($input));
    }

    /**
     * Fetch the contents given a URL.
     */
    private function fetch($url)
    {        
        if (!($handle = fopen($url, "rb"))) {
            self::debug("error: fetch: Could not open url: $url");
            return;
        }
        
        if (!($contents = stream_get_contents($handle))) {
            self::debug("Error: fetch: Could not read from url: $url");
        }
        
        fclose($handle);
        return $contents;
    }
}
?>
