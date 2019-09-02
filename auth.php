<?php
include("functions.php");

function login($username, $password) {

    $username = strtolower($username);
	if(!preg_match('/^[a-z0-9_]+$/',  $username)){
		exit;
	}

    /**
     * If we can't connect to AD, or we can't set LDAP v3 - exit
     */
    $ldapServer = "ldaps://dc-2.ada.hioa.no ldaps://dc-1.ada.hioa.no ldaps://dc-3.ada.hioa.no";
    $ldapConn = @ldap_connect($ldapServer);
    if (!$ldapConn) {
        return FALSE;
	}
    if (!@ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3)) {
        @ldap_unbind($ldapConn);
        return FALSE;
    }

    /**
     * If user exist in SYNOPSIS database populate $userlevel, $delegation and $approval variables.
     * If user doesn't exist in SYNOPSIS database prepare AD filter to check if user is member of di-ikt-f.
     */
	$synopsisUserExist = FALSE;
    $dbSynopsis = connectToSysDb();
	$username = mysqli_real_escape_string($dbSynopsis,$username);
    $query = mysqli_query($dbSynopsis,"SELECT userlevel,delegation,approval FROM synopsis_users WHERE username = '$username'") or returnError(mysqli_error($dbSynopsis));
    if (mysqli_num_rows($query) == 1) { // User exist in SYNOPSIS database
		$synopsisUserExist = TRUE;
        $row = mysqli_fetch_array($query);
        $userlevel = $row['userlevel'];
		$delegation = $row['delegation'];
		$approval = $row['approval'];
		$ldapFilter = "(&(objectClass=user)(sAMAccountName=$username))";
    }
    else { // Set filter to check if user is member of di-ikt-f.File.Groups.Employees.Managed.HiOA.ada.hioa.no
        $userlevel = 1;
		$delegation = 0;
        $approval = 0;
        $ldapFilter = "(&(objectClass=user)(sAMAccountName=$username)(memberof=CN=di-ikt-f,OU=File,OU=Groups,OU=Employees,OU=Managed,OU=HiOA,DC=ada,DC=hioa,DC=no))";
    }
	mysqli_free_result($query);
	mysqli_close($dbSynopsis);

	if(strpos($username, 'synopsis_api') === false) {
        $dn = 'ou=Active Employees,ou=Employees,ou=Managed,ou=HiOA,dc=ada,dc=hioa,dc=no';
	} else {
		$dn = 'ou=System Accounts,ou=Unmanaged,ou=HiOA,dc=ada,dc=hioa,dc=no';
	}

    /**
     * Get user information from AD and populate $userInfo. Flag user as authenticated.
     */
    $authenticated = FALSE;
	$ldapUser = $username . "@oslomet.no";
    if (ldap_bind($ldapConn, $ldapUser, $password)) {
		$attributes = array("givenName","sn","memberof","samaccountname","thumbnailPhoto"); // Return only this attributes
        $userResult = ldap_search($ldapConn, $dn, $ldapFilter, $attributes);
        $userInfo = ldap_get_entries($ldapConn, $userResult);
		if (isset($userInfo[0]["sn"][0]) ) { // surname not NULL
			$authenticated = TRUE;
		}
	}
    @ldap_unbind($ldapConn);

    if ($authenticated) {
        // Populate $_SESSION variable
        $_SESSION['synopsis'] = array (
            "username" => $userInfo[0]["samaccountname"][0],
            "firstname" => $userInfo[0]["givenname"][0],
            "lastname" => $userInfo[0]["sn"][0],
            "picture" => $userInfo[0]["thumbnailphoto"][0],
            "userlevel" => $userlevel,
            "delegation" => $delegation,
            "approval" => $approval,
            "otp" => "false",
            "otp-time" => ""
        );

        // If $username is in AD but doesn't exist in SYNOPSIS database - add it
        if(!$synopsisUserExist) {
			$dbSynopsis = connectToSysDb();
			$query = mysqli_query($dbSynopsis,"INSERT INTO synopsis_users VALUES('$username',1,0,0,NULL,0)") or returnError(mysqli_error($dbSynopsis));
            mysqli_close($dbSynopsis);
		}

        $key = getSecretKey($username);
		$otpstatus = getOtpStatus($username); // check if otp is required for user
		if( (empty($key)) || ($otpstatus == 0)) { //otp not required
			logEvent(LOG_INFO,"LOGIN_SUCCESS: User '$username' sucessfully logged in without OTP.");
			if(isset($_POST['logintype'])) {
				if($_POST['logintype'] == 'REST') { // RESTRICTED
					header('HTTP/1.1 200 '.  "Logged in successfully",true);
                    die;
				}
			} else {
				if(isset($_POST['redirect'])){
					$redirect = $_POST['redirect'];
					header("location: $redirect");
				} else {
                    //header("location:index.php");
				}
				die;
			}
		} else { // otp required
			if(isset($_POST['redirect'])){
                $redirect = $_POST['redirect'];
                header("location:otp-login.php?redirect=$redirect");
				die;
            }else{
				header("location:otp-login.php");
				die;
			}
		}
    }
    else { // not authenticated
        @sleep(5);
		logEvent(LOG_NOTICE,"LOGIN_DENIED: Failed login for user '$username' because of wrong username or password" .ldap_error($ldapConn));
		if(isset($_POST['logintype'])) {
            if($_POST['logintype'] == 'REST') {
                header('HTTP/1.1 401 '.  "Wrong username or password", true);
                die;
			}
        } else {
            header("location:login.php?error=true");
		}
    }

}

function validateOTP($username,$otp){
	$auth = false;
	$key = getSecretKey($username);
	$auth = Google2FA::verify_key($key, $otp);
	if($auth){
		$_SESSION['synopsis']['otp'] = "true";
		$_SESSION['synopsis']['otp-time'] = time()+28800;
		logEvent(LOG_INFO,"LOGIN_SUCCESS: User '$username' sucessfully logged in with OTP.");
		if(isset($_GET['redirect'])){
            $redirect = $_GET['redirect'];
            header("location: $redirect");
        }else{
            header("location:index.php");
        }
		die();
	}else{
		sleep(5);
		logEvent(LOG_NOTICE,"LOGIN_DENIED: Failed login for user '$username' because of wrong OTP");
		header("location:otp-login.php?error=true");
		die;
	}
}

if(!isset($_SESSION['synopsis']['username'])){
	login($_POST['username'],$_POST['password']);
}

if(isset($_SESSION['synopsis']['username'])){
	$key = getSecretKey($_SESSION['synopsis']['username']);
	if (empty($key)){
		returnError("Du har ikke aktivert to-faktorautentisering eller var allerede innlogget. Logg ut og prøv igjen.","plain");
	}
	else{
		validateOTP($_SESSION['synopsis']['username'],$_POST['otp']);
	}
}

?>
