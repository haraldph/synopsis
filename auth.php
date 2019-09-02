<?php
include("functions.php");

function login($username, $password) {

    $authenticated = FALSE;
	$userexists = FALSE;

    $username = strtolower($username);
	if(!preg_match('/^[a-z0-9_]+$/',  $username)){
		exit;
	}
    /**
     * Connect to domain controller LDAP server
     */
    $server = "ldaps://dc-2.ada.hioa.no ldaps://dc-1.ada.hioa.no ldaps://dc-3.ada.hioa.no";
    $ldap = @ldap_connect($server);
    if (!$ldap) {
        return $authenticated;
	}
    if (!@ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3)) {
        @ldap_unbind($ldap);
        return $authenticated;
    }

    /**
     * Connect to local SYNOPSIS database and check if user exist in SYNOPSIS's own user database. If user
     * exist retrieve $userlevel, $delegation, $approval. If not in SYNOPSIS's database check if user is member
     * of di-ikt-f. Set $userlevel, $delegation and @approval accordingly.
     */
    $dblink = connectToSysDb();
	$username = mysqli_real_escape_string($dblink,$username);
    $query = mysqli_query($dblink,"SELECT userlevel,delegation,approval FROM synopsis_users WHERE username = '$username'") or returnError(mysqli_error($dblink));
    if (mysqli_num_rows($query) == 1) { // User in SYNOPSIS database
		$userexists = TRUE;
        $row = mysqli_fetch_array($query);
        $userlevel = $row['userlevel'];
		$delegation = $row['delegation'];
		$approval = $row['approval'];
		$filter = "(&(objectClass=user)(sAMAccountName=$username))";
    }
    else { // Set filter to check if user is member of di-ikt-f
        $userlevel = 1;
		$delegation = 0;
        $approval = 0;
        $filter = "(&(objectClass=user)(sAMAccountName=$username)(memberof=CN=di-ikt-f,OU=File,OU=Groups,OU=Employees,OU=Managed,OU=HiOA,DC=ada,DC=hioa,DC=no))";
    }
	mysqli_free_result($query);
	mysqli_close($dblink);

	$ldapuser = $username . "@oslomet.no";
	if(strpos($username, 'synopsis_api') === false){
        $dn = 'ou=Active Employees,ou=Employees,ou=Managed,ou=HiOA,dc=ada,dc=hioa,dc=no';
	}else{
		$dn = 'ou=System Accounts,ou=Unmanaged,ou=HiOA,dc=ada,dc=hioa,dc=no';
	}

    if (ldap_bind($ldap, $ldapuser, $password)) {
        $authenticated = TRUE;
		$attributes = array("givenName","sn","memberof","samaccountname","thumbnailPhoto");
        $userres = ldap_search($ldap, $dn, $filter, $attributes);
        $userobject = ldap_get_entries($ldap, $userres);
		if (!isset($userobject[0]["sn"][0]) ){
			$authenticated = FALSE;
		}
	}

    @ldap_unbind($ldap);
    if ( !$authenticated ) {
        @sleep(5);
		logEvent(LOG_NOTICE,"LOGIN_DENIED: Failed login for user '$username' because of wrong username or password" .ldap_error($ldap));
		if(isset($_POST['logintype'])){
            if($_POST['logintype'] == 'REST'){
                header('HTTP/1.1 401 '.  "Wrong username or password",true);
                die;
			}
        }else{
            header("location:login.php?error=true");
		}

    }
    else{
        $_SESSION['synopsis'] = array (
            "username" => $userobject[0]["samaccountname"][0],
                "firstname" => $userobject[0]["givenname"][0],
                "lastname" => $userobject[0]["sn"][0],
                "picture" => $userobject[0]["thumbnailphoto"][0],
                "userlevel" => $userlevel,
                "delegation" => $delegation,
                "approval" => $approval,
                "otp" => "false",
                "otp-time" => ""
        );
		if(!$userexists){
			$dblink = connectToSysDb();
			$query = mysqli_query($dblink,"INSERT INTO synopsis_users VALUES('$username',1,0,0,NULL,0)") or returnError(mysqli_error($dblink));
            mysqli_close($dblink);
		}
		$key = getSecretKey($username);
		$otpstatus = getOtpStatus($username);
		if( (empty($key)) || ($otpstatus == 0)){
			logEvent(LOG_INFO,"LOGIN_SUCCESS: User '$username' sucessfully logged in without OTP.");
			if(isset($_POST['logintype'])){
				if($_POST['logintype'] == 'REST'){
					header('HTTP/1.1 200 '.  "Logged in successfully",true);
                    die;
				}
			}else{
				if(isset($_POST['redirect'])){
					$redirect = $_POST['redirect'];
					header("location: $redirect");
				}else{
                    //header("location:index.php");
				}
				die;
			}
		}else{
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
