<?php
/**
* Signature-Based Single Sign-On Framework
* TPA Adapter for
* FUDForum ( http://www.fudforum.org )
*
* Based on the Redmine adapter by Robert Lemke, 2008.
* 
* Version            : 0.1
* Last update        : 24.10.2010 by Christine Gerpheide
*
* Changelog
* 	0.1
* 		initial release
*/

// Settings BEGIN

$GLOBALS['PATH_TO_FUD_FORUM_GLOBALS_PHP'] = '../GLOBALS.php';
$GLOBALS['PATH_TO_FUD_FORUM_CORE'] = '/path/to/FUDforum';

$GLOBALS['PATH_TO_FUD_FORUM_LOGIN_SCRIPT'] = $GLOBALS['PATH_TO_FUD_FORUM_CORE'].'/scripts/forum_login.php';
$GLOBALS['PATH_TO_FUD_FORUM_USER_REG'] = $GLOBALS['PATH_TO_FUD_FORUM_CORE'].'/include/theme/default/users_reg.inc'; // Not yet used
$GLOBALS['PATH_TO_FUD_FORUM_CORE_INC'] = $GLOBALS['PATH_TO_FUD_FORUM_CORE'].'/include/core.inc'; // Not yet used

//Settings END

/**
 * Returns the supported SSO version
 *
 * @return string Supported SSO version
 */
function get_version() {
	return '2.0';
}

/**
 *  function which is called after including this file in the SSO-Agent.
 *
 *  @param
 *    User_Name    string    Username the Session will be created for
 *    remote_addr  string    Remoteaddress of the users system
 *    agent        string    Browser
 *    sso_url      string    Url where the user will be redirected after establishing a session for him
 *    sso_version  string    the protocol version of the calling agent
 *    sso_action   string    the action to perform. Right now this is either 'logon' or 'create_modify'
 *    sso_userdata string    the userdata submitted by the agent
 *
 *  @return        string    return the session data
 */
function sso($username, $ip, $agent, $sso_url, $sso_version='', $sso_action='', $sso_userdata='') {
	// Convert the sso_userdata into a proper array
	$userDataKeysAndValues = explode('|', $sso_userdata);
	$userData = array();
	foreach ($userDataKeysAndValues as $userDataKeyAndValue) {
		list($key, $value) = explode('=', $userDataKeyAndValue);
		$userData[$key] = $value;
	}
	
	// Take the requested action
	$sso_action = ($sso_version == '') ? 'logon' : $sso_action;
	switch ($sso_action) {
		case 'logon' :
			return fudforumLogon(array('username' => $username) + $userData, $sso_url);
		break;
	}
}


/**
 * Perform all actions necessary to log the user into FUDForum, such as modifying the database or creating any cookies.
 * 
 * @param array $userData User data from TYPO3
 * @param string $sso_url The URL to redirect to finish logging in
 */
function fudforumLogon($userData, $sso_url) {
	loadFudforumConf(); // Exports GLOBALSs
	try {
		$dbh = new PDO('mysql:host='. $GLOBALS['FUD_DBHOST'] . ';dbname=' . $GLOBALS['FUD_DBHOST_DBNAME'], $GLOBALS['FUD_DBHOST_USER'], $GLOBALS['FUD_DBHOST_PASSWORD']);
		$foundUserId = findUserRecord($dbh,$userData);

		if ($userId = $foundUserId) {
			// Always update the user, because at least the last_login has changed
			updateUser($dbh,$foundUserId,$userData);			
		} else {
			$userId = createUser($dbh,$userData);
		}

		// Log new user on
		if ($userId) {
			require_once($GLOBALS['PATH_TO_FUD_FORUM_LOGIN_SCRIPT']); // needed for __ses_make_sysid()
			$user_id = $userId;
			$dbh->query("DELETE FROM ".$GLOBALS['FUD_DBHOST_TBL_PREFIX']."ses WHERE user_id=".$user_id);
			$sys_id = __ses_make_sysid(($GLOBALS['FUD_OPT_2'] & 256), ($GLOBALS['FUD_OPT_3'] & 16));
			$ses_id = md5($user_id . time() . getmypid());
			$dbh->query("INSERT INTO ".$GLOBALS['FUD_DBHOST_TBL_PREFIX']."ses (ses_id, time_sec, sys_id, user_id) VALUES ('".$ses_id."', ".time().", '".$sys_id."', ".$user_id.")");
		}

	} catch (Exception $exception) {
		echo 'TYPO3 SIGSSO Error: ' . $exception->getMessage() . ' in file ' . $exception->getFile() . ' line ' . $exception->getLine();
	    syslog(LOG_ERR, 'TYPO3 SIGSSO Error: ' . $exception->getMessage() . ' in file ' . $exception->getFile() . ' line ' . $exception->getLine());
		return;
	}
	
	// Prepare sessiondata return-values in predefined format
    $returnData = array(
		'redirecturl' => $GLOBALS['FUD_WWW_ROOT'],
		'0' => array(
			'CookieName' => $GLOBALS['FUD_COOKIE_NAME'],
			'CookieValue' => $ses_id,
			'CookieExpires' => 0, //TODO $GLOBALS['COOKIE_TIMEOUT'],
			'CookiePath' => $GLOBALS['FUD_COOKIE_PATH'],
			'CookieDomain' => $GLOBALS['FUD_COOKIE_DOMAIN'],
		)
	);
   	return $returnData;
}

/**
 * Retrieve a user record from the database.  In our case, try to fnid them by email.
 * 
 * @param DBHandle $dbh The database handle
 * @param array $userData The user data from TYPO3
 * 
 * @return array The found user record
 */
function findUserRecord($dbh,$userData) {
	//TODO multiple users with the same email?
	$sql = 'SELECT id FROM '.$GLOBALS['FUD_DBHOST_TBL_PREFIX'].'users WHERE email=? LIMIT 1';
	$statement = $dbh->prepare($sql);
	if ($statement->execute(array($userData['email']))) {
		$user = $statement->fetch();
	}
	return $user['id'];
}

/**
 * Create a new user record in fudforum from the TYPO3 user data.
 * 
 * @param DBHandle $dbh The database handle
 * @param array $userData The user's data from TYPO3
 * @return int the newly created fudforum user ID
 */
 function createUser($dbh,$userData) {
	// Taken from $GLOBALS['PATH_TO_FUD_FORUM_USER_REG']
	// Needed to allow users to post
	//TODO use add_user() from user_reg.inc
	$o2 = $GLOBALS['FUD_OPT_2'];
	$users_opt = 4|16|128|256|512|2048|4096|8192|16384|131072|4194304;
	if (!($o2 & 4)) {
		$users_opt ^= 128;
	}
	if (!($o2 & 8)) {
		$users_opt ^= 256;
	}
	if ($o2 & 1) {
		$o2 ^= 1;
	}
	// No email confirmation
	$users_opt |= 131072;
 	
 	$sql = 'INSERT INTO '.$GLOBALS['FUD_DBHOST_TBL_PREFIX'].'users SET '
 			. ' login = '.$dbh->quote($userData['username'])
 			. ', email = '.$dbh->quote($userData['email'])
 			. ', alias = '.$dbh->quote($userData['username'])
 			. ', name = '.$dbh->quote($userData['name'])
 			. ', location = '.$dbh->quote($userData['country'])
 			. ', home_page = '.$dbh->quote($userData['www'])
			. ', time_zone = '.$dbh->quote($GLOBALS['SERVER_TZ'])
 			. ', last_login = NOW()'
 			. ', join_date = NOW()'
 			. ', users_opt = '.$users_opt
 			. ', passwd = '.$dbh->quote(rand().time())
 	. ';';

 	$statement = $dbh->prepare($sql);
 	if ($statement->execute()) {
		$userId = $dbh->lastInsertId();
 	}

	return $userId;	
 }
 
 /**
 * Update a user record in fudforum.
 * 
 * @param DBHandle $dbh The database handle
 * @param int $userId The fudforum user's ID
 * @param array $userData The user's data from TYPO3
 */
 function updateUser($dbh,$userId,$userData) {
 	$sql = 'UPDATE '.$GLOBALS['FUD_DBHOST_TBL_PREFIX'].'users SET '
 			. ' login = '.$dbh->quote($userData['username'])
 			. ', email = '.$dbh->quote($userData['email'])
 			. ', alias = '.$dbh->quote($userData['username'])
 			. ', name = '.$dbh->quote($userData['name'])
 			. ', location = '.$dbh->quote($userData['country'])
 			. ', home_page = '.$dbh->quote($userData['www'])
 			. ', last_login = NOW()'
	. ' WHERE id = '.$userId.';';

 	$statement = $dbh->prepare($sql);
 	$statement->execute();
 }

/**
 * Retrieve the settings for this fudforum installation.
 */
function loadFudforumConf() {
	if (isset($GLOBALS['FUD_DBHOST'])) {
		return;	// Already loaded.
	}

	if (!is_readable($GLOBALS['PATH_TO_FUD_FORUM_GLOBALS_PHP'])) {
		//TODO log error
		//syslog(LOG_ERR, 'TYPO3 SIGSSO Error: ' . 'Unable to read forum\'s GLOBALS.php. Please fix your settings!');
		return;
	}

	// Include all globals, up until the require()
	$fudforumGlobals = file_get_contents($GLOBALS['PATH_TO_FUD_FORUM_GLOBALS_PHP']);
  	eval(str_replace('<?php', '', substr_replace($fudforumGlobals, '', strpos($fudforumGlobals, 'require'))));

	// Export variables needed later
	$GLOBALS['FUD_WWW_ROOT'] = $WWW_ROOT;
	$GLOBALS['FUD_OPT_2'] = $FUD_OPT_2;
	$GLOBALS['FUD_OPT_3'] = $FUD_OPT_3;
	$GLOBALS['FUD_COOKIE_NAME'] = $COOKIE_NAME;
	$GLOBALS['FUD_COOKIE_PATH'] = $COOKIE_PATH;
	$GLOBALS['FUD_COOKIE_DOMAIN'] = $COOKIE_DOMAIN;
	$GLOBALS['FUD_COOKIE_TIMEOUT'] = $COOKIE_TIMEOUT;
	$GLOBALS['FUD_DBHOST'] = $DBHOST;
	$GLOBALS['FUD_DBHOST_USER'] = $DBHOST_USER;
	$GLOBALS['FUD_DBHOST_PASSWORD'] = $DBHOST_PASSWORD;
	$GLOBALS['FUD_DBHOST_DBNAME'] = $DBHOST_DBNAME;
	$GLOBALS['FUD_DBHOST_TBL_PREFIX'] = $DBHOST_TBL_PREFIX;
	
	// For user_reg.inc
	$GLOBALS['MAX_LOGIN_SHOW'] = $MAX_LOGIN_SHOW;
}

/**
 * Hashes a password in case it is not yet hashed
 */
//function hashPassword($password) {
//    if (substr($password, 0, 3) == '$P$') {
//	return $password;
//    } else {
//	$salt = chr(rand(48, 122)).chr(rand(48, 122)).chr(rand(48, 122)).chr(rand(48, 122));
//
//	// mark salt as md5 salt
//	$salt = '$1$'.$salt.'$';
//	return crypt($password, $salt);
//    }
//}
?>
