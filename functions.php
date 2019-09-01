<?php
ini_set('default_charset','utf-8');
session_start();

require_once("config.inc.php");
require_once("2auth.php");
require_once("lib/cfpropertylist/CFPropertyList.php");
require_once("roles-functions.php");
if ( isset($_SESSION['synopsis']) && isset($_GET['exec']) ) {
	$exec = $_GET['exec'];
    if (is_callable($exec)){
		call_user_func($exec);
	}
	else{
		returnError("Denne funksjonen er ikke tilgjengelig.");
	}
}

function getUserDevices($username){
	if($username == ""){
		returnError("Oppgi et gyldig brukernavn");
	}
    $mdtlink = connectToMdtDb();
    $query = odbc_exec($mdtlink,
    "SELECT OSDComputerName,Description,Role,MacAddress,SerialNumber,Owner,OSInstall, IDENTITYCOL as ID FROM ComputerIdentity CI JOIN Settings S ON CI.ID=S.ID
  LEFT JOIN Settings_Roles SR ON CI.ID=SR.ID WHERE Owner = '$username' AND (S.Type='C' OR S.Type='T') ORDER BY S.OSDComputerName ASC")or returnError(odbc_errormsg());
    $devices = Array();
    while($row = odbc_fetch_array($query)) {
        $type = getDeviceType(substr($row['OSDComputerName'],0,1));

        $devices[] = Array(
                "id" => $row['ID'],
          "device" => $row['OSDComputerName'],
          "type" => $type,
          "serialnumber" => $row['SerialNumber'],
                "description" => $row['Description'],
          "owner" => $row['Owner']
        );

    }
    $dblink = connectToSysDb();
    $result = mysqli_query($dblink,"SELECT * FROM synopsis_phones WHERE owner = '$username'") or returnError(mysqli_error($dblink));
    while($row = mysqli_fetch_array($result)) {
        $devices[] = Array(
                "id" => $row['id'],
          "device" => $row['imei'],
          "type" => "phone",
          "serialnumber" => $row['serial'],
          "description" => $row['description'],
          "owner" => $row['owner']
        );
    }
    $result = mysqli_query($dblink,"SELECT * FROM synopsis_mac_computers WHERE owner = '$username'") or returnError(mysqli_error($dblink));
    while($row = mysqli_fetch_array($result)) {
        $devices[] = Array(
                "id" => $row['ID'],
          "device" => $row['computername'],
          "type" => "mac",
          "serialnumber" => $row['serial'],
          "description" => $row['description'],
          "owner" => $row['owner']
        );
    }

    //$devices = array_map('utf8_encode', $devices);
    mysqli_close($dblink);
    return $devices;

}

function getLoginBySystem($computername) {
    $dblink = connectToSysDb();
    $output = "";
	$sql = "SELECT * FROM synopsis_computer_logins WHERE computername = '$computername' LIMIT 1";
    if ($result = mysqli_query($dblink, $sql)) {
        if (mysqli_num_rows($result) == 0){
            return Array("uuid" => "", "user" => "", "ip" => "" , "timestamp" => "","installdate" => "");
            exit;
        }
        while ($row = mysqli_fetch_array($result)) {
            $ip = json_decode($row['addresses']);
			if($ip != ""){
				$ip = implode(",",$ip);
			}

            $output = Array(
              "uuid" => "",
              "user" => $row['username'],
              "ip" => $ip,
              "timestamp" => date('d.m.y H:i',strtotime($row['logontime'])),
              "installdate" => ""
            );
        }
        mysqli_free_result($result);
        mysqli_close($dblink);
        return $output;
    }
}


function getDeviceType($code){
    $code = strtoupper($code);
    switch($code){
        case "L":
            return "laptop";
            break;
        case "T":
            return "tablet";
            break;
        default:
            return "unknown";
    }
}


function getSystemByLogin($login,$limit = 0){
	if($limit == 0){
		$qlimit = "";
	}else{
		$qlimit = "LIMIT $limit";
	}
	$dblink = connectToSysDb();
	$output = "";
    $sql = "SELECT computername,username,logontime FROM synopsis_computer_logins WHERE username = '$login' ORDER BY logontime DESC $qlimit";

    if ($result = mysqli_query($dblink, $sql)) {
        if (mysqli_num_rows($result) == 0){
            return $output;
            exit;
        }
        while ($row = mysqli_fetch_array($result)) {

            $output .= "'" . $row['computername'] . "',";
        }
        mysqli_free_result($result);
        mysqli_close($dblink);
        return substr($output, 0, -1);
    }


}

function getLastWindowsLogin($username){
	$system = getSystemByLogin($username,1);
	$results = array();
	if($system > " "){
		$mdtlink = connectToMdtDb();
		$query = odbc_exec($mdtlink,
    "SELECT OSDComputerName,Description, IDENTITYCOL as ID FROM ComputerIdentity CI JOIN Settings S ON CI.ID=S.ID
    WHERE S.OSDComputerName=$system AND S.Type='C'")or returnError("Feil under oppslag i database");
        while($row = odbc_fetch_array($query)) {
            $id = $row['ID'];
            $results[] = Array (
              "id" => $id,
              "name" => $row['OSDComputerName']
                );
		}
	}
	return $results;
}


function getNetworkStatus(){
	if(!isset($_GET['mac'])){
		returnError("MAC-adresse mangler");
	}
	$mac = $_GET['mac'];
	$ch = curl_init();
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, "https://nav.oslomet.no/api/1/cam/?mac=$mac&active=true");
    //curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("Authorization: Token a5a11c79adc947794f94851106504760a9dc1ed2","Content-Type: application/json"));
    //curl_setopt($ch, CURLOPT_POST, true);
	$result = curl_exec($ch);
	echo $result;
}


function windowsSearch() {
	$mdtlink = connectToMdtDb();
	$emptyquery = TRUE;
    foreach($_GET as $key=>$value) {
		$value = str_replace("'","",$value);
        $input[$key]=$value;
		if ( ($value > " ") && ($key != "exec") && ($key != "export") ) {
            $emptyquery = FALSE;
		}
	}
	if (isset($input['export']) ){
		if ($input['export'] == "on") {
			$outputtype = "csv";
		}
	}
	else {
		$outputtype = "html";

	}

	if ($emptyquery){
		returnError("Søket ble avbrutt fordi du ikke har oppgitt noen søkekriterier. Et slikt søk vil kunne ta lang tid.
		Ta kontakt med systemadministrator dersom du trenger en liste over alle objektene i databasen.");
	}
	if ($input['username'] > " ") {
		$systems = getSystemByLogin($input['username']);

		if ($systems == "") {
			returnError("Fant ingen ingen pålogginger for brukernavn ".$input['username'].".");
		}
		$query = odbc_exec($mdtlink,
    "SELECT OSDComputerName,Description,Role,MacAddress,Owner,UpdatedBy,UpdatedTime,OSInstall, IDENTITYCOL as ID FROM ComputerIdentity CI JOIN Settings S ON CI.ID=S.ID
    LEFT JOIN Settings_Roles SR ON CI.ID=SR.ID WHERE S.OSDComputerName IN (".$systems.") AND MacAddress LIKE '%".$input['mac-address']."%'
    AND CI.Description LIKE '%".$input['description']."%' AND S.OSDComputerName LIKE '%".$input['computername']."%' AND S.Type='C' ORDER BY S.OSDComputerName ASC"
    )or returnError("Feil under oppslag i database");
	}
	else {
		$ownerquery = "S.Owner LIKE '%".$input['owner']."%'";
		if ($input['owner'] <= " "){
			$ownerquery = "(S.Owner LIKE '%".$input['owner']."%' OR S.Owner IS NULL)";
		}
		$query = odbc_exec($mdtlink,
		"SELECT OSDComputerName,Description,Role,MacAddress,Owner,UpdatedBy,UpdatedTime,OSInstall, IDENTITYCOL as ID FROM ComputerIdentity CI JOIN Settings S ON CI.ID=S.ID
		LEFT JOIN Settings_Roles SR ON CI.ID=SR.ID WHERE S.OSDComputerName LIKE '%".$input['computername']."%' AND MacAddress LIKE '%".$input['mac-address']."%'
		AND CI.Description LIKE '%".$input['description']."%' AND $ownerquery ORDER BY S.OSDComputerName ASC"
		)or returnError("Feil under oppslag i database");
	}
	if(odbc_num_rows($query) > 300){
		returnError("For mange treff (flere enn 300). Prøv med flere søkekriterier");
	}
	$results = array();
	while($row = odbc_fetch_array($query)) {
		$login = getLoginBySystem($row['OSDComputerName']);
		$id = $row['ID'];
		$results[$id] = Array (
			"id" => $id,
			"name" => $row['OSDComputerName'],
			"mac-address" => $row['MacAddress'],
			"role" => $row['Role'],
			"active" => $row['OSInstall'],
			"description" => $row['Description'],
			"uuid" => $login['uuid'],
			"ip" => $login['ip'],
			"login" => $login['user'],
			"owner" => $row['Owner'],
			"timestamp" => $login['timestamp'],
			"installdate" => $login['installdate']
		);
	}

	$psarray = "";
	if (isset($input['psarray']) ){
		if($input['psarray'] == "on"){
            foreach($results as $computer) {
                $psarray .= '"'.$computer['name'].'",';
            }
            $psarray = rtrim($psarray, ",");
            $psarray = "<input type='text' readonly value='$psarray'/><br /><br />";
		}
	}
	outputMachineResults($results,$outputtype,$psarray);
}


function outputMachineResults($data,$format,$psarray = "") {
	switch ($format) {
		case "html":
			$output = "$psarray";
			$output .= "
				<table class='table table-hover'>
					<thead>
						<tr>
							<th><b>Enhetsnavn</b></th><th><b>Beskrivelse</b></th><th><b>Rolle</b></th>
							<th><b>Bruker</b></th><th><b>Sist pålogget</b></th>
						</tr>
					</thead>
					<tbody>";
			foreach($data as $computer) {
				if ($computer['active'] == 'YES') {
					$active = "";
				}
				else {
					$active = "<img width='12' style='margin-top:-1px;' title='På lager' src='/img/icons/16x16/home.png' />";
				}
				$output .= "
					<tr onclick='showProperties(\"".$computer['id']."\");'>
						<td>".$computer['name']." $active</td>
						<td>".$computer['description']."</td>
						<td>".$computer['role']."</td>
						<td>".$computer['login']."</td>
						<td>".$computer['timestamp']."</td>
					</tr>";

			}
			$output .= "</tbody></table>";
			echo $output;
			break;
		case "csv":
			$_SESSION['synopsis']['export'] = "";
			$filename = "Synopsis " . date('d.m.Y') . ".xls";
			$flag = false;
			foreach ($data as $computer) {
                if(!$flag) {
                    $_SESSION['synopsis']['export'] .= implode("\t", array_keys($computer)) . "\r\n";
					$flag = true;
                }
                array_walk($computer, 'cleanData');
                $_SESSION['synopsis']['export'] .= implode("\t", array_values($computer)) . "\r\n";
            }
			echo "export";
			break;
	}
}

function mobileSearch(){
    $dblink = connectToSysDb();
    $emptyquery = TRUE;
    foreach($_GET as $key=>$value) {
        $input[$key]=$value;
        if ( ($value > " ") && ($key != "exec") && ($key != "export") ) {
            $emptyquery = FALSE;
        }
    }
    if (isset($input['export']) ){
        if ($input['export'] == "on") {
            $outputtype = "csv";
        }
    }
    else {
        $outputtype = "html";
    }

    if ($emptyquery){
        returnError("Søket ble avbrutt fordi du ikke har oppgitt noen søkekriterier. Et slikt søk vil kunne ta lang tid.
    Ta kontakt med systemadministrator dersom du trenger en liste over alle objektene i databasen.");
    }
	else{
		if($input['assettag'] > ""){
			$query = "SELECT * FROM synopsis_phones WHERE owner LIKE '%".$input['owner']."%' AND description LIKE '%".$input['description']."%' AND assettag LIKE '%".$input['assettag']."'";
		}else{
			$query = "SELECT * FROM synopsis_phones WHERE owner LIKE '%".$input['owner']."%' AND description LIKE '%".$input['description']."%' AND imei LIKE '%".$input['imei']."%' AND serial LIKE '%".$input['serial']."%'";
		}
		$result = mysqli_query($dblink, $query) or returnError(mysqli_error($dblink));
	}
	if (mysqli_num_rows($result) == 0){
		returnError("Ingen treff på ditt søk i mobile enheter.");
	}
	$results = array();
	while ($row = mysqli_fetch_array($result)) {
		$id = $row['id'];
		$results[$id] = Array (
      "id" => $row['id'],
			"assettag" => $row['assettag'],
			"owner" => $row['owner'],
      "description" => $row['description'],
      "imei" => $row['imei'],
      "serial" => $row['serial']
    );
	}
	mysqli_free_result($result);
	mysqli_close($dblink);
	outputPhoneResults($results,$outputtype);
}

function getPhoneProperties(){
	$dblink = connectToSysDb();
	$id = mysqli_real_escape_string($dblink,$_GET['phone']);
	$result = mysqli_query($dblink, "SELECT * FROM synopsis_phones WHERE id ='$id'") or returnError(mysqli_error($dblink));
	while ($row = mysqli_fetch_array($result)) {
		if($row['serial'] > ""){
			$mdm = getAirwatchDevice("Serialnumber",$row['serial']);
		}else{
			$mdm = getAirwatchDevice("ImeiNumber",$row['imei']);
		}
        $object = Array (
          "id" => $row['id'],
                "assettag" => $row['assettag'],
          "owner" => $row['owner'],
          "description" => $row['description'],
          "imei" => $row['imei'],
          "serial" => $row['serial'],
                "mdm" => $mdm,
                "comment" => $row['comment']
        );
    }
	mysqli_free_result($result);
    mysqli_close($dblink);
	echo json_encode($object);

}


function editPhoneObject(){
    $dblink = connectToSysDb();
	foreach($_POST as $key=>$value) {
        $input[$key]=mysqli_real_escape_string($dblink,$value);
	}
	$owner = strtolower($input['owner']);
    if ( (!validateOwner($owner)) || ($owner <= "") ){
        returnError("'".$owner."' er ikke en gyldig avdelingskode eller brukernavn");
    }
	if($input['assettag'] > ""){
		$assettag = $input['assettag'];
		if(!is_numeric($assettag)){
			returnError("Ugyldig tyverinummer");
		}
	}
	if(!isset($assettag) || $input['imei'] > ""){
		if(strlen($input['imei']) <> 15){
            returnError("Du har oppgitt en ugyldig IMEI.");
        }
	}
	mysqli_query($dblink, "UPDATE synopsis_phones SET owner = '$owner', description = '".$input['description']."', comment = '".$input['comment']."',
	imei = '".$input['imei']."' WHERE id ='".$input['id']."'") or returnError(mysqli_error($dblink));
    mysqli_close($dblink);
	logEvent(LOG_INFO,"SYN_OPERATION: Update phone object '".$input['imei']."' performed by '".$_SESSION['synopsis']['username']."'.");
}

function outputPhoneResults($data,$format) {
    switch ($format) {
        case "html":
            $output = "
        <table class='table table-hover'>
          <thead>
            <tr>
              <th><b>Eier</b></th><th><b>Beskrivelse</b></th><th><b>IMEI</b></th><th><b>Serienummer</b><th><b>Tyverinummer</b></th></th>
            </tr>
          </thead>
          <tbody>";
            foreach($data as $device) {
                $output .= "
          <tr onclick='showPhoneProperties(\"".$device['id']."\");' class='tablelistrow'>
            <td>".$device['owner']."</td>
            <td>".$device['description']."</td>
            <td>".$device['imei']."</td>
            <td>".$device['serial']."</td>
						<td>".$device['assettag']."</td>
          </tr>";

            }
            $output .= "</tbody></table>";
            echo $output;
            break;
		case "csv":
			$_SESSION['synopsis']['export'] = "";
            $filename = "Synopsis " . date('d.m.Y') . ".xls";
            $flag = false;
            foreach ($data as $device) {
                if(!$flag) {
                    $_SESSION['synopsis']['export'] .= implode("\t", array_keys($device)) . "\r\n";
                    $flag = true;
                }
                array_walk($device, 'cleanData');
                $_SESSION['synopsis']['export'] .= implode("\t", array_values($device)) . "\r\n";
            }
            echo "export";
            break;
	}
}


function macSearch(){
	$dblink = connectToSysDb();
    $emptyquery = TRUE;
    foreach($_GET as $key=>$value) {
        $input[$key]=$value;
        if ( ($value > " ") && ($key != "exec") && ($key != "export") ) {
            $emptyquery = FALSE;
        }
    }
    if (isset($input['export']) ){
        if ($input['export'] == "on") {
            $outputtype = "csv";
        }
    }
    else {
        $outputtype = "html";
    }

    if ($emptyquery){
        returnError("Søket ble avbrutt fordi du ikke har oppgitt noen søkekriterier. Et slikt søk vil kunne ta lang tid.
    Ta kontakt med systemadministrator dersom du trenger en liste over alle objektene i databasen.");
    }
    else{
        $result = mysqli_query($dblink, "SELECT * FROM synopsis_mac_computers WHERE owner LIKE '%".$input['owner']."%' AND description LIKE '%".$input['description']."%'
    AND computername LIKE '%".$input['computername']."%' AND serial LIKE '%".$input['serial']."%'") or returnError(mysqli_error($dblink));
    }
    if (mysqli_num_rows($result) == 0){
        returnError("Ingen treff på ditt søk i Mac OS-enheter.");
    }
    $results = array();
	while ($row = mysqli_fetch_array($result)) {
        $id = $row['ID'];
        $results[$id] = Array (
          "id" => $row['ID'],
          "owner" => $row['owner'],
          "description" => $row['description'],
          "computername" => $row['computername'],
          "serial" => $row['serial']
        );
    }
	mysqli_free_result($result);
    mysqli_close($dblink);
	$output = "
        <table class='table table-hover'>
          <thead>
            <tr>
              <th><b>Maskinnavn</b></th><th><b>Beskrivelse</b></th><th><b>Serienummer</b></th><th><b>Eier</b></th>
            </tr>
          </thead>
          <tbody>";
    foreach($results as $device) {
        $output .= "
          <tr onclick='showMacProperties(\"".$device['id']."\");' class='tablelistrow'>
            <td>".$device['computername']."</td>
            <td>".$device['description']."</td>
            <td>".$device['serial']."</td>
            <td>".$device['owner']."</td>
          </tr>";

    }
    $output .= "</tbody></table>";
    echo $output;
}

function linuxSearch(){
    $link = connectToSysDb();
    foreach($_GET as $key=>$value) {
        $$key=mysqli_real_escape_string($link,$value);
    }
	$result = mysqli_query($link, "SELECT * FROM linux_computers WHERE name LIKE '%$name%' AND description LIKE '%$description%' AND (ip4address LIKE '%$ipaddress%' OR ip6address LIKE '%$ipaddress%')") or returnError(mysqli_error($link));

    if (mysqli_num_rows($result) == 0){
        returnError("Ingen treff på ditt søk i Linux-servere.");
    }
    $results = array();
    while ($row = mysqli_fetch_array($result)) {
        $id = $row['id'];
		if($row['ip4address'] == ""){
			$ipstack = "IPv6";
		}elseif($row['ip6address'] == ""){
			$ipstack = "IPv4";
		}else{
			$ipstack = "IPv4/6";
		}
        $results[$id] = Array (
          "id" => $row['id'],
          "name" => $row['name'],
          "description" => $row['description'],
                "ipstack" => $ipstack
        );
    }
    mysqli_free_result($result);
    mysqli_close($link);
    $output = "
        <table class='table table-hover'>
          <thead>
            <tr>
              <th>Navn</th><th>Beskrivelse</th><th>IP-stack</th>
            </tr>
          </thead>
          <tbody>";
    foreach($results as $device) {
        $output .= "
          <tr onclick='showLinuxProperties(\"".$device['id']."\");' class='tablelistrow'>
            <td>".$device['name']."</td>
            <td>".$device['description']."</td>
						<td>".$device['ipstack']."</td>
          </tr>";

    }
    $output .= "</tbody></table>";
    echo $output;
}


function cleanData(&$str) {
    $str = preg_replace("/\t/", "\\t", $str);
    $str = preg_replace("/\r?\n/", "\\n", $str);
    if(strstr($str, '"')) $str = '"' . str_replace('"', '""', $str) . '"';
}

function addEditSystemUser(){
	if($_SESSION['synopsis']['userlevel'] != 9){
        returnError("Du må være administrator for å kunne redigere brukere");
    }
	$dblink = connectToSysDb();
    $username = mysqli_real_escape_string($dblink,$_POST['username']);
	if($username <= " "){
		returnError("Ugyldig brukernavn");
	}
	if($username == $_SESSION['synopsis']['username']){
        returnError("Du kan ikke endre dine egne rettigheter");
    }
	$userlevel = mysqli_real_escape_string($dblink,$_POST['userlevel']);
	if(isset($_POST['delegation'])){
		$delegation = 1;
	}else{
		$delegation = 0;
	}
	if(isset($_POST['approval'])){
        $approval = 1;
    }else{
        $approval = 0;
    }

    $result = mysqli_query($dblink,"UPDATE synopsis_users SET userlevel = $userlevel,delegation = $delegation,approval = $approval WHERE username = '$username'")or returnError(mysqli_error($dblink));
    if($result){
        logEvent(LOG_INFO,"SYN_OPERATION: Updated permissions for '$username' performed by '".$_SESSION['synopsis']['username']."'.");
	}
}

function getSystemUser(){
	$dblink = connectToSysDb();
	$username = mysqli_real_escape_string($dblink,$_GET['username']);
    $result = mysqli_query($dblink,"SELECT username,userlevel,delegation,approval,(otpkey IS NOT NULL) AS otpset FROM synopsis_users WHERE username = '$username'")or returnError(mysqli_error($dblink));
    $user = mysqli_fetch_assoc($result);
	echo json_encode($user);
}

function getSystemUsersList() {
	$output = "
    <table id='system-users-table' class='table table-hover'>
      <thead>
        <tr>
          <th><b>Bruker</b></th><th><b>Brukernivå</b></th></th><th>To-faktor</b></th>
        </tr>
      </thead>
      <tbody>";
	$dblink = connectToSysDb();
	$result = mysqli_query($dblink,"SELECT username,userlevel,delegation,otpkey FROM synopsis_users")or returnError(mysqli_error($dblink));
	while ($row = mysqli_fetch_array($result)) {
		$delegation = "";
		if ($row['delegation'] == 1){
			$delegation = "<i class='fa fa-check'></i>";
		}
		if($row['otpkey'] == ""){
            $otp = "Ikke aktivert";
        }else{
            $otp = "Aktivert";
		}

		$output .= "
    <tr class='tablelistrow' onclick='getSystemUser(\"".$row['username']."\");'>
      <td>".$row['username']."</td>
      <td>".getUserlevelName($row['userlevel'])."</td>
			<td>$otp</td>
    </tr>";

	}
	mysqli_free_result($result);
    mysqli_close($dblink);
	$output .= "</tbody></table>";
	echo $output;
}

function resetOTP(){
	$dblink = connectToSysDb();
	$username = mysqli_real_escape_string($dblink,$_POST['username']);
	if ($_SESSION['synopsis']['username'] == $username){
		returnError("Du kan ikke nullstille din egen to-faktornøkkel","plain");
	}
    if( ($_SESSION['synopsis']['userlevel'] != 9) || ($_SESSION['synopsis']['delegation'] != 1) ){
		returnError("Du må være administrator og ha tilgang til å gi adminrettigheter for å kunne nullstille to-faktornøkler","plain");
	}
	if (!getOtpLoginStatus()){
		returnError("Du må være logget inn med to-faktor for å utføre denne operasjonen","plain");
	}
    $result = mysqli_query($dblink,"UPDATE synopsis_users SET otpkey = '', requireotp = 0 WHERE username = '$username'")or returnError(mysqli_error($dblink));
	logEvent(LOG_INFO,"SYN_OPERATION: Reset of 2FA key for user '$username' performed by '".$_SESSION['synopsis']['username']."'.");

}

function getUserlevelName($level) {
	$replace = Array("Standard","Utvidet","Administrator");
	$search = Array("1","5","9");
	return str_replace($search,$replace,$level);
}

function approveDiscardedObject(){
	$approvedby = $_SESSION['synopsis']['username'];
	(int)$id = $_POST['id'];
	$type = $_POST['type'];

    switch($type){
        case "pc":
            $mdtlink = connectToMdtDb();
            $query = odbc_exec($mdtlink,"UPDATE DiscardedComputers SET approvedby = '$approvedby',approved_date = CURRENT_TIMESTAMP()
        WHERE id = $id AND approvedby = NULL AND discardedby != '$approvedby'")or returnError(odbc_errormsg());
            echo "Enheten ble godkjent kassert.";
            break;
        case "mac":
            $dblink = connectToSysDb();
            $id = mysqli_real_escape_string($dblink,$id);
            $query = mysqli_query($dblink,"UPDATE synopsis_mac_computers_discarded SET approvedby = '$approvedby',approved_date = NOW()
        WHERE ID = $id AND approvedby IS NULL AND discardedby != '$approvedby'")or returnError(mysqli_error($dblink));
            echo "Enheten ble godkjent kassert.";
            break;
        case "mobile":
            $dblink = connectToSysDb();
            $id = mysqli_real_escape_string($dblink,$id);
            $query = mysqli_query($dblink,"UPDATE synopsis_phones_discarded SET approvedby = '$approvedby',approved_date = NOW()
        WHERE id = $id AND approvedby IS NULL AND discardedby != '$approvedby'")or returnError(mysqli_error($dblink));
            echo "Enheten ble godkjent kassert.";
            break;
    }

}

function approveDiscardedObjectsBulk(){
	$approvedby = $_SESSION['synopsis']['username'];
	foreach($_POST as $key=>$value) {
        $input[$key]=$value;
    }
	if ($input['discardedby'] == ""){
		$discardedby = "";
	}else{
		$discardedby = "discardedby = '".$input['discardedby']."' AND";
	}

	switch($input['type']){
		case "pc":
			$mdtlink = connectToMdtDb();
			if ($input['runtype'] == "simulate"){
                $query = odbc_exec($mdtlink,"SELECT AssetTag FROM DiscardedComputers
				WHERE $discardedby ApprovedBy = NULL AND DiscardedBy != '$approvedby'")or returnError(odbc_errormsg());
				$rows = odbc_num_rows($query);
				echo "$rows Windows-enheter vil bli godkjent kassert med dette filteret.";
			}else{
				$query = odbc_exec($mdtlink,"UPDATE DiscardedComputers SET approvedby = '$approvedby',approved_date = CURRENT_TIMESTAMP()
				WHERE $discardedby approvedby = NULL AND discardedby != '$approvedby'")or returnError(odbc_errormsg());
                $rows = odbc_num_rows($query);
                echo "$rows Windows-enheter ble godkjent kassert.";
			}
            break;
		case "mac":
			if ($input['runtype'] == "simulate"){
				$dblink = connectToSysDb();
				$query = mysqli_query($dblink,"SELECT assettag FROM synopsis_mac_computers_discarded WHERE $discardedby approvedby IS NULL AND discardedby != '$approvedby'")or returnError(mysqli_error($dblink));
				$rows = mysqli_num_rows($query);
                echo "$rows enheter vil bli godkjent kassert med dette filteret.";
			}else{
				$dblink = connectToSysDb();
                $query = mysqli_query($dblink,"UPDATE synopsis_mac_computers_discarded SET approvedby = '$approvedby',approved_date = NOW()
				WHERE $discardedby approvedby IS NULL AND discardedby != '$approvedby'")or returnError(mysqli_error($dblink));
                $rows = mysqli_affected_rows($dblink);
                echo "$rows Mac OS-enheter ble godkjent kassert.";
			}
            break;
		case "mobile":
            if ($input['runtype'] == "simulate"){
                $dblink = connectToSysDb();
                $query = mysqli_query($dblink,"SELECT imei FROM synopsis_phones_discarded WHERE $discardedby approvedby IS NULL AND discardedby != '$approvedby'")or returnError(mysqli_error($dblink));
                $rows = mysqli_num_rows($query);
                echo "$rows mobile enheter vil bli godkjent kassert med dette filteret.";
            }else{
                $dblink = connectToSysDb();
                $query = mysqli_query($dblink,"UPDATE synopsis_phones_discarded SET approvedby = '$approvedby',approved_date = NOW()
        WHERE $discardedby approvedby IS NULL AND discardedby != '$approvedby'")or returnError(mysqli_error($dblink));
                $rows = mysqli_affected_rows($dblink);
                echo "$rows mobile enheter ble godkjent kassert.";
            }
            break;
	}

}
function getDiscardedObjects() {
	$user = $_SESSION['synopsis']['username'];
	foreach($_GET as $key=>$value) {
        $input[$key]=$value;
	}
	if (!is_numeric($input['assettag']) && ($input['owner'] <= "")){
		returnError("Tyverinummer må være et tall");
	}
	switch($input['type']){
		case "pc":
			$link = connectToMdtDb();
			$query = odbc_exec($link,"SELECT * FROM DiscardedComputers WHERE AssetTag LIKE '".$input['assettag']."%'")or returnError(odbc_errormsg());
			$output = "
			  <table id='discarded-table' class='table'>
  			  <thead>
    			  <tr>
	    	  	  <th><b>Tyverinummer</b></th>
							<th><b>MAC-adresse</b></th>
							<th><b>Serienummer</b></th>
							<th><b>Eier</b></th>
							<th><b>Kassert av</b></th>
							<th><b>Kasseringsdato</b></th>
							<th></th>
		        </tr>
  		    </thead>
    		  <tbody>";
			while($row = odbc_fetch_array($query)) {
                $output .= "
	  	  <tr class='tablelistrow'>
	  			<td>".$row['AssetTag']."</td>
          <td>".$row['MacAddress']."</td>
          <td>".$row['SerialNumber']."</td>
					<td>".$row['Owner']."</td>
	    	  <td>".$row['DiscardedBy']."</td>
  	    	<td>".date("d.m.y",strtotime($row['DiscardedDate']))."</td>";
                if($row['ApprovedBy'] == ""){
                    $output .= "<td><button class='btn btn-primary' onclick='restoreDiscardedObject(\"".$row['ID']."\");' title='Omgjør kassering'><i class='fa fa-undo'></i></button></td>";
                }else{
                    $output .= "<td><button class='btn btn-primary' disabled title='Omgjøring er ikke mulig når objektet er bekreftet kassert.><i class='fa fa-undo'></i></button></td>";
                }
                $output .= "</tr>";
			}
            $output .= "</tbody></table>";
			echo $output;
            break;
		case "mac":
            $dblink = connectToSysDb();
            $query = mysqli_query($dblink,"SELECT * FROM synopsis_mac_computers_discarded WHERE assettag LIKE '".$input['assettag']."%'")or returnError(mysqli_error($dblink));
            $output = "
        <table id='discarded-table' class='table'>
          <thead>
            <tr>
              <th><b>Tyverinummer</b></th>
              <th><b>Serienummer</b></th>
              <th><b>Eier</b></th>
              <th><b>Kassert av</b></th>
              <th><b>Kasseringsdato</b></th>
							<th><b>Begrunnelse</b></th>
            </tr>
          </thead>
          <tbody>";
            while($row = mysqli_fetch_array($query)) {
                $output .= "
        <tr class='tablelistrow'>
          <td>".$row['assettag']."</td>
          <td>".$row['serial']."</td>
          <td>".$row['owner']."</td>
          <td>".$row['discardedby']."</td>
          <td>".date("d.m.y",strtotime($row['discarded_date']))."</td>
					<td>".$row['reason']."</td>
        </tr>";
            }
            $output .= "</tbody></table>";
            echo $output;
            break;
		case "mobile":
            $dblink = connectToSysDb();
            $query = mysqli_query($dblink,"SELECT * FROM synopsis_phones_discarded WHERE (imei LIKE '".$input['assettag']."%' OR serial LIKE '".$input['assettag']."%') AND owner LIKE '".$input['owner']."%'")or returnError(mysqli_error($dblink));
            $output = "
        <table id='discarded-table' class='table'>
          <thead>
            <tr>
              <th><b>Tyverinummer</b></th>
              <th><b>Serienummer</b></th>
              <th><b>Eier</b></th>
              <th><b>Kassert av</b></th>
              <th><b>Kasseringsdato</b></th>
							<th><b>Begrunnelse</b></th>
							<th>Bekreft</th>
            </tr>
          </thead>
          <tbody>";
            while($row = mysqli_fetch_array($query)) {
				if($row['discardedby'] == $user){
					$disabled = "disabled";
				}else{
					$disabled = "";
				}
                $output .= "
        <tr class='tablelistrow'>
          <td>".$row['imei']."</td>
          <td>".$row['serial']."</td>
          <td>".$row['owner']."</td>
          <td>".$row['discardedby']."</td>
          <td>".date("d.m.y",strtotime($row['discarded_date']))."</td>
					<td>".$row['reason']."</td>";
                if($row['approvedby'] == ""){
                    $output .= "<td><button class='btn btn-primary' $disabled onclick='approveDiscardedObject(\"".$row['id']."\",\"mobile\",this);' title='Bekreft kassering'><i class='fa fa-check'></i></button></td>";
                }else{
                    $output .= "<td>".$row['approvedby']."</td>";
                }
                $output .= "</tr>";
            }
            $output .= "</tbody></table>";
            echo $output;
            break;

	}
}

function getRoles($selectedrole = "", $elementid = "rolelist") {
	$link = connectToMdtDb();
	$result = odbc_exec($link,"SELECT * FROM RoleIdentity ORDER BY Role ASC")or die(odbc_errormsg());
	$output = "<select name='role' class='form-control' id='$elementid'>";
	if ( isset($_SESSION['synopsis']['userlevel']) ) {
		$userlevel = $_SESSION['synopsis']['userlevel'];
	}
	else{
		$userlevel = 0;
	}
    while($row = odbc_fetch_array($result)){
		if( ($userlevel < 9) && ($row['Production'] == 0) ) {
			$disabled = "disabled='disabled'" ;
		}
		else {
			$disabled = "";
		}
		$selected = ($row['Role'] == $selectedrole) ? "selected='selected'" : "";
        $output .= "<option $disabled $selected value='".$row['Role']."'>".$row['Role']."</option>";
	}
    $output .= "</select>";
    echo $output;

}

function getRoleProperties() {
	$link = connectToMdtDb();
	$rolename = $_GET['rolename'];
    $result = odbc_exec($link, "SELECT * FROM RoleIdentity WHERE Role = '$rolename'")or die(odbc_errormsg());
	while($row = odbc_fetch_array($result)){
		$status = $row['Production'];
	}
	echo $status;
}

function setRoleProperties() {
    $link = connectToMdtDb();
    $rolename = $_GET['rolename'];
	$rolestatus = $_GET['rolestatus'];
    $result = odbc_exec($link,"UPDATE RoleIdentity SET Production = '$rolestatus' WHERE Role = '$rolename'")or returnError(odbc_errormsg());
}

function getLinuxRoles($outputtype = 'html'){
	$link = connectToSysDb();
	$result = mysqli_query($link,"SELECT id,name,description FROM linux_roles")or returnError("Kunne ikke laste roller");
	if($outputtype == "html"){
		$output = "<ul style='height: 225px;overflow-y: scroll;' class='list-group' id='linux-role-list'>";
        if ( isset($_SESSION['synopsis']['userlevel']) ) {
            $userlevel = $_SESSION['synopsis']['userlevel'];
        }
        else{
            $userlevel = 0;
        }
        while($row = mysqli_fetch_array($result)){
            $output .= "<li class='list-group-item list-group-item-action' data-toggle='modal' data-target='#linux-role-dialog'
			data-role-id='".$row['id']."' data-role-name='".$row['name']."' data-role-description='".$row['description']."'>".$row['name']." - <small class='text-muted'>".$row['description']."</small></li>";
        }
        $output .= "</ul>";
        echo $output;
	}else if($outputtype == "select"){
		$output = "<select class='form-control' id='linux-role-list' name='roles[]' multiple='multiple'>";
        while($row = mysqli_fetch_array($result)){
            $output .= "<option value=".$row['id'].">".$row['name']."</option>";
        }
        $output .= "</select>";
        echo $output;
	}
}

function addEditLinuxRole(){
	$link = connectToSysDb();
	foreach($_POST as $key=>$value) {
        $input[$key]=mysqli_real_escape_string($link,$value);
    }
	if($input['description'] <= ""){
		returnError("Oppgi en beskrivelse av rollen");
	}
	if($input['name'] <= ""){
        returnError("Oppgi et rollenavn");
    }
	if(is_numeric($input['id'])){
		mysqli_query($link,"UPDATE linux_roles SET name='".$input['name']."', description = '".$input['description']."' WHERE id = '".$input['id']."'")or returnError("Kunne ikke oppdatere rollen");
	}else{
		mysqli_query($link,"INSERT INTO linux_roles (name,description) VALUES('".$input['name']."','".$input['description']."')")or returnError("Kunne ikke lagre ny rolle");
	}
}


function validateLocation($building,$room){
	$building = strtoupper($building);
	$room = strtoupper($room);
	$ch = connectToWs();
	$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "lifrooms";
    curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_POSTFIELDS, '');
    $result = curl_exec($ch);
	if(curl_error($ch)){
		returnError("Feil under henting av data fra BAS");
	}
	$locations = json_decode($result,true);
    $locations = array_change_key_case($locations[0],CASE_UPPER);
    if(isset($locations[$building])){
        $roomlist = array_map('strtoupper',$locations[$building]);
        if(array_search($room,$roomlist) !== FALSE){
            return true;
        }
		else{
            return false;
        }
    }else{
        return false;
    }

}


function setAdminProperties(){
	if (getOtpLoginStatus() == false){
        returnError("Logg inn med engangskode");
    }
	if ($_SESSION['synopsis']['delegation'] != 1){
        returnError("Du har ikke rettigheter til å delegere admintilgang");
    }

	foreach($_POST as $key=>$value) {
        $input[$key]=$value;
	}
	$username = $input['username'];
    if($username <= " "){
        returnError("Brukernavn mangler. Prøv på nytt.");
    }
	$type = $input['type'];
	$validtypes = array("none", "localadmin", "classroomadmin");
	if(in_array($type,$validtypes) == FALSE ){
        returnError("Du har ikke oppgitt en gyldig administratortype.");
    }
	$ch = connectToWs();
	switch($type){
		case "none":
			$data = array("username" => $username,"classroomadmin" => true,"localadmin" => true);
			$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "delpcadmin";
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            $result = curl_exec($ch);
            logEvent(LOG_INFO,"SYN_OPERATION: Delete admin privileges for '$username' performed by '".$_SESSION['synopsis']['username']."'.");
			break;
		case "localadmin":
			if($input['current'] == "classroomadmin"){
				$data = array("username" => $username,"classroomadmin" => true,"localadmin" => "false");
				$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "delpcadmin";
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                $result = curl_exec($ch);
				if($result){
                    logEvent(LOG_INFO,"SYN_OPERATION: Delete admin privileges (CLASSROOM) for '$username' performed by '".$_SESSION['synopsis']['username']."'.");
				}
			}
            $data = array("username" => $username,"classroomadmin" => false,"limitedadmin" => array());
			$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "addpcadmin";
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            $result = curl_exec($ch);
            logEvent(LOG_INFO,"SYN_OPERATION: Add admin privileges (LIMITED) for '$username' performed by '".$_SESSION['synopsis']['username']."'.");
			break;
		case "classroomadmin":
			$data = array("username" => $username,"classroomadmin" => true,"limitedadmin" => array());
			$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "addpcadmin";
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            $result = curl_exec($ch);
			echo $result;
			echo json_encode($data);
            logEvent(LOG_INFO,"SYN_OPERATION: Add admin privileges (CLASSROOM) for '$username' performed by '".$_SESSION['synopsis']['username']."'.");
			break;
	}
}

function addAdminComputer(){
	if (getOtpLoginStatus() == false){
        returnError("Logg inn med engangskode");
    }
	if ($_SESSION['synopsis']['delegation'] != 1){
        returnError("Du har ikke rettigheter til å delegere admintilgang");
    }

	$username = $_POST['username'];
    if($username <= " "){
        returnError("Brukernavn mangler. Prøv på nytt.");
    }
	$computer = $_POST['computer'];
    if($computer <= " "){
        returnError("Maskinnavn mangler. Prøv på nytt.");
    }
	$data = array("username" => $username,"classroomadmin" => false,"limitedadmin" => array($computer));
    $ch = connectToWs();
	$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "addpcadmin";
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    $result = curl_exec($ch);
	echo "$result $username $computer";
    logEvent(LOG_INFO,"SYN_OPERATION: Add admin privileges on computer $computer for '$username' performed by '".$_SESSION['synopsis']['username']."'.");

}

function deleteAdminComputer(){
    if (getOtpLoginStatus() == false){
        returnError("Logg inn med engangskode");
    }
    if ($_SESSION['synopsis']['delegation'] != 1){
        returnError("Du har ikke rettigheter til å delegere admintilgang");
    }

    $username = $_POST['username'];
    if($username <= " "){
        returnError("Brukernavn mangler. Prøv på nytt.");
    }
    $computer = $_POST['computer'];
    if($computer <= " "){
        returnError("Maskinnavn mangler. Prøv på nytt.");
    }
    $data = array("username" => $username,"classroomadmin" => false,"localadmin" => false, "limitedadmin" => array($computer));
    $ch = connectToWs();
	$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "delpcadmin";
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    $result = curl_exec($ch);
    echo "$result $username $computer";
    logEvent(LOG_INFO,"SYN_OPERATION: Delete admin privileges on computer $computer for '$username' performed by '".$_SESSION['synopsis']['username']."'.");

}



function getAdminProperties($username = "", $json = true){
	if($username == ""){
		$username = $_GET['username'];
	}
    $ch = connectToWs();
	$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "pcadmins";
    curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $username);
    $result = curl_exec($ch);
	if($json){
		echo $result;
	}else{
        return json_decode($result,true);
	}

}

function usersSearch(){
    $ch = connectToWs();
	$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "tsemployee";
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $_GET['term']);
    $result = curl_exec($ch);
	$suggestions = json_decode($result,true);
    $results = array();
	foreach($suggestions as $person){
        $results[] = array("label" => $person['value'], "value" => $person['login']);
    }
    echo json_encode($results);
}

/*
function usersSearch(){
$dblink = connectToPybasDb();
$term = pg_escape_string($_GET['term']);
$query = pg_query($dblink,"SELECT firstname||' '||lastname,login FROM views.view_oa_employee
WHERE (firstname ILIKE '%$term%') OR (lastname ILIKE '%$term%') OR (firstname||' '||lastname ILIKE '%$term%') ORDER BY firstname,lastname LIMIT 10")
or returnError("Klarte ikke å slå opp bruker i PyBAS");
$results = array();
while ($row = pg_fetch_row($query)){
$results[] = array("label" => $row[0], "value" => $row[1]);
}
echo json_encode($results);
}*/

function getUserUnit($user){
	$dblink = connectToPybasDb();
    $query = pg_query($dblink,"SELECT units FROM views.view_oa_employee_all WHERE login = '$user'") or returnError("Klarte ikke å slå opp bruker i PyBAS");
	if (pg_num_rows($query) != 1){
        $result = "N/A";
    }
	while ($row = pg_fetch_assoc($query)){
        $result = convertPgArray($row['units']);
    }
	return $result[0];
}


function registerWifiUser(){
	if ($_SESSION["synopsis"]['userlevel'] < 1) {
        returnError("Du har ikke tilgang til å registrere anonyme trådløskontoer");
	}

	$ch = connectToWs();
	foreach($_POST as $key=>$value) {
        $$key=$value;
    }
	$startdate = "$year-$month-$day";
	$enddate = "$toyear-$tomonth-$today";

	$data = array(
		"firstname" => $firstname,
		"lastname" => $lastname,
		"startdate" => $startdate,
		"enddate" => $enddate,
		"email" => $email,
		"contact" => $contact,
		"officer" => $_SESSION['synopsis']['username'],
	);
    $url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "guestwifi";
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    $result = curl_exec($ch);

    if(curl_error($ch)){
        returnError("Feil under henting av data fra BAS");
    }
	if(strpos($result,'"status": "error"')){
		returnError("Det oppsto en feil: $result");
	}
	echo $result;

}

function validateOwner($owner, $ownertype = 'all'){
	$valid = false;

    $ch = connectToWs();

	if( $ownertype == 'all' || $ownertype == 'person' ){
		$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "synemp";
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $owner);
        $result = curl_exec($ch);

        if(curl_error($ch)){
            returnError("Feil under henting av data fra BAS");
        }

		$person = json_decode($result,true);

        if(isset($person[$owner])){
            return true;
        }
    }

	if ( $ownertype == 'all' || $ownertype == 'unit' ){
		$ch = connectToWs();
		$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "isunit";
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $owner);
        $result = curl_exec($ch);

        if(curl_error($ch)){
            returnError("Feil under henting av data fra BAS");
        }

        $validunit = json_decode($result,true);
		if($validunit['valid'] == true){
			return true;
		}
    }
	return $valid;

}

function getLocations($type) {
    $output = "<datalist id='$type'>";
    $ch = connectToWs();
	$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "lifrooms";
    curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_POSTFIELDS, "");
    $result = curl_exec($ch);
    if(curl_error($ch)){
		echo "<datalist id='$type'></datalist>";
		return;
    }
	if(curl_getinfo($ch,CURLINFO_HTTP_CODE) != 200){
		echo "<datalist id='$type'></datalist>";
		return;
	}
    $locations = json_decode($result,true);
    $locations = array_change_key_case($locations[0],CASE_UPPER);

    switch($type) {
        case "buildings":
			foreach($locations as $key => $value) {
                $output .= "<option value='".$key."'>";
			}
            break;
        case "rooms":
			foreach($locations as $key => $value) {
				foreach($value as $room){
                    $output .= "<option value='".$room."'>";
				}
            }
            break;
    }
    $output .= "</datalist>";
    echo $output;
}

function addNewPhone(){
	$dblink = connectToSysDb();
	foreach($_POST as $key=>$value) {
        $input[$key]=mysqli_real_escape_string($dblink,$value);
    }

	if($input['assettag'] > ""){
        $assettag = $input['assettag'];
        if(!is_numeric($assettag)){
            returnError("Ugyldig tyverinummer");
        }
    }
    if(!isset($assettag) || $input['imei'] > ""){
        if(strlen($input['imei']) <> 15){
            returnError("Du har oppgitt en ugyldig IMEI.");
        }
    }

	$owner = strtolower($input['owner']);
	if($owner <= ""){
        returnError("Du har ikke oppgitt en eier.");
    }
	if($input['imei'] > ""){
		$duplicate = mysqli_query($dblink,"SELECT imei FROM synopsis_phones WHERE imei = '".$input['imei']."'");
        if(mysqli_num_rows($duplicate) >= 1){
            returnError("Et annet objekt med samme IMEI finnes allerede");
        }
	}
	if(isset($assettag)){
		$duplicate = mysqli_query($dblink,"SELECT 1 FROM synopsis_phones WHERE assettag = '$assettag'");
        if(mysqli_num_rows($duplicate) >= 1){
            returnError("Et annet objekt med samme tyverinummer finnes allerede");
        }
	}

	if (!validateOwner($owner)){
		returnError("'".$owner."' er ikke en gyldig avdelingskode eller brukernavn");
	}

	mysqli_query($dblink,"INSERT INTO synopsis_phones (assettag,imei,serial,owner,description,comment) VALUES('".$input['assettag']."','".$input['imei']."','" . $input['serialnumber'] . "','".
	$owner ."','" . $input['description'] ."','" . $input['comment'] ."')")or returnError(mysqli_error($dblink));
	mysqli_close($dblink);
	echo "Enheten ble lagret";
}

function addEditLinuxServer(){
	if($_SESSION['synopsis']['userlevel'] < 9){
        returnError("Du har ikke rettigheter til å administrere Linux-servere",'plain');
    }
	$link = connectToSysDb();
    foreach($_POST as $key=>$value) {
		if($key != "roles"){
            $$key=mysqli_real_escape_string($link,$value);
		}else{
			$roles = $value;
		}
    }

	if (isset($_POST['id']) ) {
        (int)$id = $_POST['id'];
        mysqli_query($link,"UPDATE linux_computers SET name='$name',description='$description',macaddress='$macaddress',
		ip4address='$ip4address',ip4gateway='$ip4gateway',ip4subnetmask='$ip4subnetmask',ip4dns='$ip4dns',
		ip6address='$ip6address',ip6gateway='$ip6gateway',ip6subnetprefixlength='$ip6subnetprefixlength',ip6dns='$ip6dns',managed='$managed',comment='$comment' WHERE id = '$id'")or returnError(mysqli_error($link));
		logEvent(LOG_INFO,"SYN_OPERATION: Update Linux server object '$name' performed by '".$_SESSION['synopsis']['username']."'.");
		mysqli_query($link, "DELETE FROM linux_role_mapping WHERE computerid = '$id'")or returnError(mysqli_error($link));
		foreach($roles as $role){
            mysqli_query($link, "INSERT INTO linux_role_mapping VALUES ('$role','$id')")or returnError(mysqli_error($link));
        }
    }
    else {
		//New server
		$duplicate = mysqli_query($link,"SELECT name FROM linux_computers WHERE name = '$name'");
        if(mysqli_num_rows($duplicate) >= 1){
            returnError("Et annet objekt med dette navnet finnes allerede");
        }
		if($ip4address == ""){
			$ip4dns = "";
		}
		if($ip6address == ""){
            $ip6dns = $ip6subnetprefixlength = "";
        }
        mysqli_query($link,"INSERT INTO linux_computers (name,description,macaddress,ip4address,ip4gateway,ip4subnetmask,ip4dns,ip6address,ip6gateway,ip6subnetprefixlength,ip6dns,managed,comment)
		VALUES('$name','$description','$macaddress','$ip4address','$ip4gateway','$ip4subnetmask','$ip4dns','$ip6address','$ip6gateway','$ip6subnetprefixlength','$ip6dns','$managed','$comment')")or returnError(mysqli_error($link));
		$id = mysqli_insert_id($link);
		logEvent(LOG_INFO,"SYN_OPERATION: New Linux server '$name' added by '".$_SESSION['synopsis']['username']."'.");
		foreach($roles as $role){
            mysqli_query($link, "INSERT INTO linux_role_mapping VALUES ('$role','$id')")or returnError(mysqli_error($link));
        }
    }
	mysqli_close($link);
	echo "Objektet ble lagret";
}

function addEditMacObject() {
	$serial = $description = $owner = $assetag = "";
	$dblink = connectToSysDb();
	foreach($_POST as $key=>$value) {
        $input[$key]=mysqli_real_escape_string($dblink,$value);
    }

	if ( isset($input['assettag']) ) {
        $assettag = $input['assettag'];
    }
	if ( isset($input['serial']) ) {
        $serial = $input['serial'];
    }else{
		returnError("Du har ikke oppgitt et gyldig serienummer.");
	}

    switch($input['type']) {
        case "mac-desktop":
            if ( ($assettag < " ") || (!is_numeric($assettag)) ){
                returnError("Du har ikke oppgitt et gyldig tyverinummer.");
            }
            $name = "M" . $input['assettag'];
			$manifest = "gen-desktop";
            $building = strtoupper($input['building']);
            $room = strtoupper($input['room']);

			$owner = strtolower($input['owner']);
			if($owner > ""){
                if (!validateOwner($owner)){
                    returnError("'".$owner."' er ikke en gyldig avdelingskode eller brukernavn");
                }
			}
            if (validateLocation($building,$room)) {
				$description = $building . "-" . $room . "-" . $input['assettag'];
            }
            else {
                returnError($building . "-" . $room . " er ikke en gyldig plassering.");
            }
            break;
        case "mac-laptop":
            if  ( ($assettag < " ") || (!is_numeric($assettag)) ) {
                returnError("Du har ikke oppgitt et gyldig tyverinummer.");
            }
            $name = "L" . $input['assettag'];
			$manifest = "gen-laptop";
            $owner = strtolower($input['owner']);
            if ( (!validateOwner($owner)) || ($owner <= "") ){
                returnError("'".$owner."' er ikke en gyldig avdelingskode eller brukernavn");
            }

            $building = strtoupper($input['building']);
            $room = strtoupper($input['room']);
            if (validateLocation($building,$room)) {
                $description = $building . "-" . $room . "-" . $input['assettag'];
            }
            else {
                returnError($building . "-" . $room . " er ikke en gyldig plassering.");
            }
            break;
	}

	if ( isset($_POST['id']) ) {
		(int)$id = $_POST['id'];
		mysqli_query($dblink,"UPDATE synopsis_mac_computers SET serial = '$serial',assettag = '" . $input['assettag'] . "',owner = '$owner',
		description = '$description',computername = '$name' WHERE ID = $id")or returnError(mysqli_error($dblink));
        mysqli_close($dblink);
		logEvent(LOG_INFO,"MAC_OPERATION: Mac with name '$name' and serial number '$serial' was updated by user '".$_SESSION['synopsis']['username']."'.");
	}
	else {
		mysqli_query($dblink,"INSERT INTO synopsis_mac_computers (serial,assettag,owner,description,computername) VALUES('$serial','" . $input['assettag'] . "','".
  	$owner ."','$description','$name')")or returnError(mysqli_error($dblink));
        mysqli_close($dblink);
	}

	$deployresult = false;
	/*
	$filename = "deploystudio_template.plist";
    $fh = fopen($filename, 'r');
    $template = fread($fh, filesize($filename));
    fclose($fh);
	if ($owner == "")
    $owner = "-";
    $template = str_replace("%COMPUTERNAME%",$name,$template);
    $template = str_replace("%OWNER%",$owner,$template);
    $template = str_replace("%SERIALNUMBER%",$serial,$template);
	$template = str_replace("%DESCRIPTION%",$description,$template);
	$tmpfile = tmpfile();
    fwrite($tmpfile, $template);
    $fileinfo = stream_get_meta_data($tmpfile);
    $deployresult = updateDeployStudio($serial,$fileinfo['uri']);
    fclose($tmpfile);
     */
	$manifestresult = exec("./create_manifest_file.sh $name $manifest");
	if ( $manifestresult == "TRUE"){
		$manifesttext = "Manifest-fil ble opprettet.";
	}
	else{
		$manifesttext = "Manifest-fil ble ikke opprettet.";
	}

	if ($deployresult){
		logEvent(LOG_INFO,"MAC_OPERATION: Mac with name '$name' and serial number '$serial' was added by user '".$_SESSION['synopsis']['username']."'.");
		echo "Enheten ble lagret og registrert i Deploystudio. $manifesttext";
	}
	else{
		logEvent(LOG_INFO,"MAC_OPERATION: Mac with name '$name' and serial number '$serial' was added by user '".$_SESSION['synopsis']['username']."'.");
        echo "Enheten ble lagret, men ikke registrert i Deploystudio. $manifesttext";
	}
}

function addNewObject() {
	foreach($_POST as $key=>$value) {
        $input[$key]=$value;
    }
	$macaddress = $description = $owner = $assettag = $serialnumber = $ip = $gateway = $netmask = $dns = $serverfields = $servervalues = "";
	$mdttype = "C";
	if($input['type'] != "tablet") {
		$macaddress = strtoupper($input['mac-address']);
		if(!preg_match("/^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$/",$macaddress)) {
			returnError("Du har oppgitt en ugyldig MAC adresse.");
		}
	}
	if ( isset($input['assettag']) ) {
		$assettag = $input['assettag'];
	}

	$link = connectToMdtdb();
	if ( ($assettag == "") && ($input['type'] != "tablet") ){
		$duplicateres = odbc_exec($link,"SELECT COUNT(*) AS counter FROM ComputerIdentity WHERE MacAddress = '$macaddress'") or returnError(odbc_errormsg());
	}
	else if ($input['type'] == "tablet") {
		$duplicateres = odbc_exec($link,"SELECT COUNT(*) AS counter FROM ComputerIdentity WHERE AssetTag = '".$assettag."' OR SerialNumber = '".$input['serialnumber']."'") or returnError(odbc_errormsg());
	}
	else{
		$duplicateres = odbc_exec($link,"SELECT COUNT(*) AS counter FROM ComputerIdentity WHERE MacAddress = '$macaddress'
		OR AssetTag = '".$assettag."' AND MacAddress <> ''") or returnError(odbc_errormsg());
	}

	$duplicate = odbc_fetch_array($duplicateres);
	odbc_free_result($duplicateres);

	$discardedres = odbc_exec($link,"SELECT COUNT(*) as counter FROM DiscardedComputers WHERE (MacAddress = '$macaddress' AND MacAddress <> '') OR (AssetTag = '".$assettag."' AND AssetTag <> '')") or returnError(odbc_errormsg());
	$discarded = odbc_fetch_array($discardedres);
    odbc_free_result($discardedres);


	if ( ($duplicate['counter'] >= 1) || ($discarded['counter'] >= 1) ){
		returnError("Et objekt med denne MAC-adressen,serienummer eller tyverinummer finnes allerede.");
	}

	switch($input['type']) {
		case "desktop":
			if ( ($assettag < " ") || (!is_numeric($assettag)) ){
                returnError("Du har ikke oppgitt et gyldig tyverinummer.");
			}
			$name = "P" . $input['assettag'];
			$building = strtoupper($input['building']);
			$room = strtoupper($input['room']);
			if (validateLocation($building,$room)) {
				$description = $building . "-" . $room . "-" . $input['assettag'];
			}
			else {
				returnError($building . "-" . $room . " er ikke en gyldig plassering.");
			}
			break;
		case "laptop":
			if  ( ($assettag < " ") || (!is_numeric($assettag)) ) {
                returnError("Du har ikke oppgitt et gyldig tyverinummer.");
            }
			$name = "L" . $input['assettag'];
			$owner = strtolower($input['owner']);
			if ( (!validateOwner($owner)) || ($owner <= "") ){
                returnError("'".$owner."' er ikke en gyldig avdelingskode eller brukernavn");
            }

			$description =  $input['assettag'];
			$building = strtoupper($input['building']);
            $room = strtoupper($input['room']);
            if (validateLocation($building,$room)) {
                $description = $building . "-" . $room . "-" . $input['assettag'];
            }
            else {
                returnError($building . "-" . $room . " er ikke en gyldig plassering.");
            }
			break;

        case "virtual":
            if ($assettag < " ") {
                returnError("Du har ikke oppgitt et gyldig tyverinummer.");
            }
            $name = "V" . $input['assettag'];
            $description = $input['description'];
            break;

        case "tablet":
            if  ( ($assettag < " ") || (!is_numeric($assettag)) ) {
                returnError("Du har ikke oppgitt et gyldig tyverinummer.");
            }
            $serialnumber = $input['serialnumber'];
            $name = "T" . $input['assettag'];
            $description = $input['description'];
            $owner = strtolower($input['owner']);
            if (!validateOwner($owner) ){
			    returnError("'".$owner."' er ikke en gyldig avdelingskode eller brukernavn");
            }

            $mdttype = "T";
            break;

        case "server":
            $name = $input['servername'];
            if (strstr($name, '.') != FALSE){
                returnError("Du kan ikke oppgi FQDN som servernavn. Benytt kun kortnavn.");
            }
            $description = $input['description'];
            //IPv4
            $ip = $input['ip-address'];
            $gateway = $input['gateway'];
            $netmask = $input['netmask'];
            $dns = $input['dns'];
            //IPv6
            $ipv6 = $input['ipv6-address'];
            $ipv6gateway = $input['ipv6-gateway'];
            $ipv6prefixlength = $input['prefix-length'];
            $ipv6dns = $input['ipv6-dns'];

            $ou = $input['ou'];
            $serverfields = ",MachineObjectOU,OSDAdapter0DNSServerList,OSDAdapter0EnableDHCP,OSDAdapter0Gateways,
				OSDAdapter0IPAddressList,OSDAdapter0SubnetMask,OSDAdapterCount,OSDAdapter0EnableDNSRegistration,OSDAdapter0EnableFullDNSRegistration,CustomIPv6DNSAddress,CustomIPv6Gateway,
				CustomIPv6SubnetPrefixLength,CustomIPv6Address";
            $servervalues = ",'$ou','$dns','FALSE','$gateway','$ip','$netmask','1','TRUE','TRUE','$ipv6dns','$ipv6gateway','$ipv6prefixlength','$ipv6'";
            break;
	}

	$insertresult = odbc_exec($link,"INSERT INTO ComputerIdentity VALUES('$description','".$assettag.
	"','','$serialnumber','".$macaddress."')")or returnError(odbc_errormsg());

	if ($insertresult != false){
		$computerid = odbc_exec($link,"SELECT MAX(ID) AS CompId FROM ComputerIdentity")or returnError(odbc_errormsg());
		$computerid = odbc_fetch_array($computerid);
        $computerid = $computerid['CompId'];
		$user = $_SESSION['synopsis']['username'];
		$timestamp = date("d.m.Y H:i");

		odbc_exec($link,"INSERT INTO Settings (Type,ID,OSInstall,OSDComputerName,UpdatedBy,UpdatedTime,Owner $serverfields)
    VALUES ('$mdttype','$computerid','YES','".$name."','$user','$timestamp','".$owner."'$servervalues)")or returnError(odbc_error());

		if ($mdttype == "C") {
            odbc_exec($link,"INSERT INTO Settings_Roles (Type,ID,Sequence,Role) VALUES ('C','$computerid','1','".$input['role']."')")or returnError(odbc_errormsg());
		}
	}
	else {
		returnError("Kunne ikke lagre objektet. Kontakt systemansvarlig hvis feilen vedvarer.");
	}
	logEvent(LOG_INFO,"MDT_OPERATION: New object was registred with the name '$name' by user '".$_SESSION['synopsis']['username']."'.");
	echo "Enheten ble lagret med navnet $name";
}

function deleteObject(){
	if ($_SESSION['synopsis']['userlevel'] < 9){
		returnError("Du har ikke rettigheter til å slette objekter!");
	}
	(int)$id = $_POST['id'];
    $link = connectToMDTDb();
    $query = odbc_exec($link,"SELECT CI.AssetTag,S.OSDComputerName, IDENTITYCOL as ID
  FROM ComputerIdentity CI JOIN Settings S ON CI.ID=S.ID WHERE CI.ID='$id'") or returnError(odbc_errormsg());
    $row = odbc_fetch_array($query);
    $computername = $row['OSDComputerName'];
	odbc_free_result($query);
	$delres = odbc_exec($link,"DELETE FROM ComputerIdentity WHERE ID='$id'") or returnError(odbc_errormsg());
	if ($delres){
		logEvent(LOG_INFO,"MDT_OPERATION: Computer '$computername' was deleted from MDT by user '".$_SESSION['synopsis']['username']."'.");
        $adobject = findAdObject($computername);
        if ($adobject['count'] > 0){
            deleteADObject($computername);
        }
    }
}

function restoreDiscardedObject(){
	(int)$id = $_POST['id'];
	$reason = $_POST['reason'];
	$link = connectToMDTDb();
	$query = odbc_exec($link, "SELECT AssetTag,MacAddress FROM DiscardedComputers WHERE ID='$id'")or returnError(odbc_errormsg());
	$result = odbc_fetch_array($query);
	odbc_free_result($query);
	$delres = odbc_exec($link,"DELETE FROM DiscardedComputers WHERE ID='$id'") or returnError(odbc_errormsg());
    if ($delres){
		logEvent(LOG_INFO,"MDT_OPERATION: Computer ".$result['AssetTag']." / ".$result['MacAddress'] ." was restored from discarded objects by user '".$_SESSION['synopsis']['username']."'. Reason: $reason.");
	}
}

function discardObject() {
	(int)$id = $_POST['id'];
	$reason = $_POST['reason'];
	$link = connectToMDTDb();
	$query = odbc_exec($link,"SELECT CI.AssetTag,S.OSDComputerName,S.OSDAdapterCount, IDENTITYCOL as ID
	FROM ComputerIdentity CI JOIN Settings S ON CI.ID=S.ID WHERE CI.ID='$id'") or returnError(odbc_errormsg());
	$row = odbc_fetch_array($query);
	odbc_free_result($query);
	$computername = $row['OSDComputerName'];
	if($row['OSDAdapterCount'] == 1){
		if($_SESSION['synopsis']['userlevel'] < 9){
			returnError("Du har ikke rettigheter til å kassere servere",'plain');
		}
	}
	if ($row['AssetTag'] > " "){
		$assettag = $row['AssetTag'];
	}
	else{
		$assettag = substr($computername,1);
	}
	$updatedby = $_SESSION['synopsis']['username'];
	odbc_exec($link,"INSERT INTO DiscardedComputers ( DiscardedBy,DiscardedDate,AssetTag,SerialNumber,MacAddress)
  SELECT '$updatedby',getdate(),'$assettag',SerialNumber,MacAddress FROM ComputerIdentity WHERE ID='$id'") or returnError(odbc_errormsg());
	$delres = odbc_exec($link,"DELETE FROM ComputerIdentity WHERE ID='$id'") or returnError(odbc_errormsg());
	if ($delres){
		$adobject = findAdObject($computername);
		if ($adobject['count'] > 0){
			deleteADObject($computername);
		}
		logEvent(LOG_INFO,"MDT_OPERATION: Computer '$computername' was discarded by user '".$_SESSION['synopsis']['username']."'. Reason: $reason");
	}
}


function discardMacObject() {
	(int)$id = $_POST['id'];
	$discardedby = $_SESSION['synopsis']['username'];
	$link = connectToSysDb();
	(int)$id = mysqli_real_escape_string($link,$_POST['id']);
	$reason = mysqli_real_escape_string($link,$_POST['reason']);
	$serialquery =  mysqli_query($link,"SELECT serial,computername FROM synopsis_mac_computers WHERE ID = '$id'");
	$serialrow = mysqli_fetch_array($serialquery);
	$serial = $serialrow[0];
	$name = $serialrow[1];
	mysqli_autocommit($link, FALSE);
	$ch = connectToMunkiApi();
    $url = "https://report.munki.oslomet.no/index.php?/manager/delete_machine/".$serial;
    curl_setopt($ch, CURLOPT_URL, $url);
    $result = curl_exec($ch);
	$mdm = getAirwatchDevice("Serialnumber",$serial);
	if(isset($mdm['Udid'])){

	}
	try {
		$insertresult = mysqli_query($link,"INSERT INTO synopsis_mac_computers_discarded (assettag,serial,description,owner,computername,discarded_date,discardedby,reason)
		SELECT assettag,serial,description,owner,computername, NOW() AS discarded_date, '$discardedby' as discardedby, '$reason' as reason FROM synopsis_mac_computers WHERE ID = '$id'");
		if (! $insertresult){
			throw new Exception('Klarte ikke å overføre maskinen til kasseringstabellen.');
		}
		$deleteresult = mysqli_query($link,"DELETE FROM synopsis_mac_computers WHERE ID = '$id'");
		if (! $deleteresult){
            throw new Exception('Klarte ikke å slette maskinen fra maskintabellen.');
        }
		$munkideleteresult = curl_exec($ch);
		if(! $munkideleteresult){
			logEvent(LOG_INFO,"SYN_OPERATION: Mac computer with '$serial' was not deleted from MunkiReport. Might not exist.");
		}

		$manifestresult = exec("./delete_manifest_file.sh $name");
        if ( $manifestresult == "TRUE"){
            $manifesttext = "Manifest-fil ble slettet for $name.";
        }
        else{
            $manifesttext = "Manifest-fil ble ikke slettet for $name.";
        }

	}
    catch (Exception $ex ){
		mysqli_rollback($link);
		mysqli_close($link);
		return returnError("Det oppsto en feil under kassering av enheten: " .$ex->getMessage());
	}
	logEvent(LOG_INFO,"SYN_OPERATION: Mac Computer with '$serial' was discarded by user '".$_SESSION['synopsis']['username']."'. Reason: $reason");
	mysqli_commit($link);
	mysqli_close($link);
}

function discardPhoneObject() {
    $discardedby = $_SESSION['synopsis']['username'];
    $link = connectToSysDb();
	(int)$id = mysqli_real_escape_string($link,$_POST['id']);
    $reason = mysqli_real_escape_string($link,$_POST['reason']);
    mysqli_autocommit($link, FALSE);
    try {
        $insertresult = mysqli_query($link,"INSERT INTO synopsis_phones_discarded (imei,serial,description,owner,discarded_date,discardedby,reason)
    SELECT imei,serial,description,owner,NOW() AS discarded_date, '$discardedby' as discardedby,'$reason' as reason FROM synopsis_phones WHERE ID = '$id'");
        if (! $insertresult){
            throw new Exception('Klarte ikke å overføre telefonen til kasseringstabellen.');
        }
        $deleteresult = mysqli_query($link,"DELETE FROM synopsis_phones WHERE ID = '$id'");
        if (! $deleteresult){
            throw new Exception('Klarte ikke å slette telefonen fra telefontabellen.');
        }
    }
    catch (Exception $ex ){
        mysqli_rollback($link);
        mysqli_close($link);
        return returnError("Det oppsto en feil under kassering av enheten: " .$ex->getMessage());
    }
    mysqli_commit($link);
    mysqli_close($link);
}


function editObject() {
	foreach($_POST as $key=>$value) {
        $input[$key]=$value;
    }
	(int)$id = $input['id'];
	$description = $owner = $assettag = $ip = $gateway = $netmask = $dns = $serverfields = $servervalues = "";
	if($input['type'] != "tablet") {
        $macaddress = strtoupper($input['mac-address']);
        if(!preg_match("/^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$/",$macaddress)) {
            returnError("Du har oppgitt en ugyldig MAC adresse.");
        }
    }
    if ( isset($input['assettag']) ) {
        $assettag = $input['assettag'];
    }

	switch($input['type']) {
        case "desktop":
			if ($input['assettag'] <= ""){
				returnError("Du har ikke oppgitt et tyverinummer for denne enheten!");
			}
            $name = "P" . $input['assettag'];
            $building = strtoupper($input['building']);
            $room = strtoupper($input['room']);
            if (validateLocation($building,$room)) {
                $description = $building . "-" . $room . "-" . $input['assettag'];
            }
            else {
                returnError($building . "-" . $room . " er ikke en gyldig plassering.");
            }
            break;
        case "laptop":
			if ($input['assettag'] <= ""){
                returnError("Du har ikke oppgitt et tyverinummer for denne enheten!");
            }
            $name = "L" . $input['assettag'];
			$owner = strtolower($input['owner']);
            if ( (!validateOwner($owner)) || ($owner <= "") ){
                returnError("'".$owner."' er ikke en gyldig avdelingskode eller brukernavn");
            }
            $description =  $input['assettag'];
            if ( ($input['building'] > " ") && ($input['room'] > " ") ) {
                $building = strtoupper($input['building']);
                $room = strtoupper($input['room']);
                if (validateLocation($building,$room)) {
                    $description = $building . "-" . $room . "-" . $input['assettag'];
                }
                else {
                    returnError($building . "-" . $room . " er ikke en gyldig plassering.");
                }
            }
            break;

        case "virtual":
            $name = "V" . $input['assettag'];
            $description = $input['description'];
            break;

        case "tablet":
            if  ( ($assettag < " ") || (!is_numeric($assettag)) ) {
                returnError("Du har ikke oppgitt et gyldig tyverinummer.");
            }
            $macaddress = "";
            $serialnumber = $input['serialnumber'];
            $name = "T" . $input['assettag'];
            $description = $input['description'];
            $owner = strtolower($input['owner']);
            if (!validateOwner($owner) ){
                returnError("'".$owner."' er ikke en gyldig avdelingskode eller brukernavn");
            }

            $mdttype = "T";
            break;

        case "server":
            $name = $input['servername'];
            $description = $input['description'];
            //IPv4
            $ip = $input['ip-address'];
            $gateway = $input['gateway'];
            $netmask = $input['netmask'];
            $dns = $input['dns'];
            //IPv6
            $ipv6 = $input['ipv6-address'];
            $ipv6gateway = $input['ipv6-gateway'];
            $ipv6prefixlength = $input['prefix-length'];
            $ipv6dns = $input['ipv6-dns'];

            $ou = $input['mdt-ou'];

            $servervalues = ",MachineObjectOU = '$ou',OSDAdapter0DNSServerList = '$dns',OSDAdapter0Gateways = '$gateway',
        OSDAdapter0IPAddressList = '$ip',OSDAdapter0SubnetMask = '$netmask',CustomIPv6DNSAddress= '$ipv6dns',
				CustomIPv6Gateway = '$ipv6gateway',CustomIPv6SubnetPrefixLength = '$ipv6prefixlength',CustomIPv6Address = '$ipv6'";
            break;
    }
	$link = connectToMDTDb();
	$updateres = odbc_exec($link,"UPDATE ComputerIdentity SET Description = '$description', AssetTag = '$assettag',MacAddress = '$macaddress' WHERE ID='$id'")or returnError("ODBC:".odbc_errormsg());

    if ($updateres){
		$user = $_SESSION['synopsis']['username'];
		$timestamp = date("d.m.Y H:i");

		odbc_exec($link,"UPDATE Settings SET OSInstall='YES',OSDComputerName = '$name',UpdatedBy = '$user',UpdatedTime = '$timestamp',Owner = '$owner' $servervalues WHERE ID='$id'")or returnError(odbc_errormsg());
        odbc_exec($link,"UPDATE Settings_Roles SET Role = '".$input['role']."' WHERE ID='$id'")or returnError("ODBC:".odbc_errormsg());
		$activedirectory = findADObject($name);
		if ($activedirectory['count'] == 1){
			echo "test";
			$descriptionupdate = updateADDescription($name,$description);

			$roleidquery = odbc_exec($link,"SELECT ID FROM RoleIdentity WHERE Role='".$input['role']."'")or returnError(odbc_errormsg());
			while($roleidrow = odbc_fetch_array($roleidquery)){

			}

			$roleouquery = odbc_exec($link,"SELECT MachineObjectOU FROM Settings WHERE ID='".$roleidrow['ID']."' AND Type='R'" )or returnError(odbc_errormsg());
			$roleourow = odbc_fetch_array($roleouquery);
			moveADObject($name, $roleourow[0]);

		}else{
			$descriptionupdate = "Ikke funnet i Active Directory.";
		}

	}
    else {
        returnError("Kunne ikke lagre objektet. Kontakt systemansvarlig hvis feilen vedvarer.");
    }
    echo "Objektet ble oppdatert. $descriptionupdate";
}

function getProperties() {
	foreach($_GET as $key=>$value) {
        $input[$key]=$value;
    }

	if ($input['computer'] > "") {
		$mdtlink = connectToMdtdb();
		$query = odbc_exec($mdtlink,
    "SELECT SerialNumber,AssetTag,OSDComputerName,Description,Role,MacAddress,OSInstall,Owner,UpdatedBy,UpdatedTime,
		MachineObjectOU,OSDAdapter0DNSServerList,OSDAdapter0EnableDHCP,OSDAdapter0Gateways,OSDAdapter0IPAddressList,
		OSDAdapter0SubnetMask,OSDAdapterCount,CustomIPv6DNSAddress,CustomIPv6Gateway,CustomIPv6SubnetPrefixLength,
		CustomIPv6Address, IDENTITYCOL as ID FROM ComputerIdentity CI JOIN Settings S ON CI.ID=S.ID
    LEFT JOIN Settings_Roles SR ON CI.ID=SR.ID WHERE CI.ID = '".$input['computer']."'")or returnError(odbc_errormsg());
    }
    $results = array();
	$serverproperties = NULL;
    while($row = odbc_fetch_array($query)) {
        $login = getLoginBySystem($row['OSDComputerName']);
		$adattributes = getADProperties($row['OSDComputerName']);
        $id = $row['ID'];
		if ( (substr($row['OSDComputerName'],0,1) == "P") && (is_numeric(substr($row['OSDComputerName'],1))) )	{
			$type = "desktop";
		}
		else if ( (substr($row['OSDComputerName'],0,1) == "L") && (is_numeric(substr($row['OSDComputerName'],1))) ) {
			$type = "laptop";
		}
		else if ( (substr($row['OSDComputerName'],0,1) == "V") && (is_numeric(substr($row['OSDComputerName'],1,4))) ) {
            $type = "virtual";
        }
        else if ( (substr($row['OSDComputerName'],0,1) == "T") && (is_numeric(substr($row['OSDComputerName'],1,4))) ) {
            $type = "tablet";
        }

		else if ( $row['OSDAdapterCount'] == 1 ){
			if($_SESSION['synopsis']['userlevel'] < 9){
				returnError("Du har ikke rettigheter til å vise servere",'plain');
			}
			$type = "server";
			$serverproperties = Array(
				"ou" => $row['MachineObjectOU'],
				"dns" => $row['OSDAdapter0DNSServerList'],
				"gateway" => $row['OSDAdapter0Gateways'],
				"ip" => $row['OSDAdapter0IPAddressList'],

    		"netmask" => $row['OSDAdapter0SubnetMask'],
				"ipv6-address" =>  $row['CustomIPv6Address'],
				"ipv6-dns" =>  $row['CustomIPv6DNSAddress'],
				"ipv6-gateway" =>  $row['CustomIPv6Gateway'],
				"prefix-length" =>  $row['CustomIPv6SubnetPrefixLength'],
			);
		}

		else{
			$type = "";
		}
		$sccm = getSCCMProperties($row['OSDComputerName']);
        $results = Array (
          "id" => $id,
                "type" => $type,
                "assettag" => $row['AssetTag'],
          "name" => $row['OSDComputerName'],
          "mac-address" => $row['MacAddress'],
                "serial" => $row['SerialNumber'],
          "role" => $row['Role'],
                "active" => $row['OSInstall'],
          "description" => utf8_encode($row['Description']),
                "owner" => $row['Owner'],
                "uuid" =>  $login['uuid'],
          "ip" => $login['ip'],
          "login" => $login['user'],
          "timestamp" => $login['timestamp'],
                "installdate" => $sccm['installdate'],
                "exists" => $adattributes['exists'],
                "dn" => $adattributes['dn'],
                "groups" => $adattributes['groups'],
                "recoverykey" => $adattributes['recoverykey'],
                "adminpassword" => $adattributes['adminpassword'],
                "server" => $serverproperties,
                "sccm" => $sccm
        );
    }
	echo json_encode($results);
}


function getLinuxProperties(){
	$link = connectToSysDb();
	$id = mysqli_real_escape_string($link,$_GET['id']);
    $query = mysqli_query($link,"SELECT * FROM linux_computers WHERE id = '$id'")or returnError(mysqli_error($link));
    $result = "";
	$rolequery = mysqli_query($link,"SELECT roleid FROM linux_role_mapping WHERE computerid = '$id'")or returnError(mysqli_error($link));
	$roles = array();
	while ($row = mysqli_fetch_array($rolequery)) {
        array_push($roles,$row['roleid']);
    }
    while ($row = mysqli_fetch_array($query)) {
        $result = Array(
          "id" => $row['id'],
          "name" => $row['name'],
          "description" => $row['description'],
          "ip4address" => $row['ip4address'],
          "ip4gateway" => $row['ip4gateway'],
                "ip4subnetmask" => $row['ip4subnetmask'],
                "ip4dns" => $row['ip4dns'],
                "ip6address" => $row['ip6address'],
          "ip6gateway" => $row['ip6gateway'],
                "ip6subnetprefixlength" => $row['ip6subnetprefixlength'],
          "ip6dns" => $row['ip6dns'],
                "managed" => $row['managed'],
                "roles" => $roles,
                "comment" => $row['comment']
        );
    }
    mysqli_close($link);
    echo json_encode($result);

}

function getMacProperties(){
	foreach($_GET as $key=>$value) {
        $input[$key]=$value;
    }
	$id = $input['computer'];
	$dblink = connectToSysDb();
	$query = mysqli_query($dblink,"SELECT * FROM synopsis_mac_computers WHERE ID = '$id'")or returnError(mysqli_error($dblink));
	$result = "";
	while ($row = mysqli_fetch_array($query)) {
		if (substr($row['computername'],0,1) == "M")
			$type = "desktop";
		else
			$type = "laptop";

		$munkidblink = connectToMunki();
		$munkiquery = mysqli_query($munkidblink,"SELECT * FROM machine LEFT JOIN reportdata USING (serial_number)WHERE serial_number = '".$row['serial']."'")or returnError(mysqli_error($munkidblink));
		$ch = connectToMunkiApi();
        $url = "https://report.munki.oslomet.no/index.php?/clients/detail/".$row['serial'];
        curl_setopt($ch, CURLOPT_URL, $url);
        $result = curl_exec($ch);

		$ip = $username = $reportdate = "";
		if (mysqli_num_rows($munkiquery) == 1) {
			while ($munkirow = mysqli_fetch_array($munkiquery)){
				$ip = $munkirow['remote_ip'];
				$username = $munkirow['console_user'];
				$reportdate = date('d.m.Y H:i',$munkirow['timestamp']);
			}
		}
		$mdminfo = getAirWatchDevice("Serialnumber",$row['serial']);
		$result = Array(
			"id" => $row['ID'],
			"type" => $type,
			"assettag" => $row['assettag'],
			"serial" => $row['serial'],
			"name" => $row['computername'],
			"description" => $row['description'],
			"owner" => $row['owner'],
			"ip" => $ip,
			"user" => $username,
			"reportdate" => $reportdate,
			"mdm" => $mdminfo
		);
	}
	mysqli_close($dblink);
	echo json_encode($result);
}

function getAirWatchDevice($searchby = "Serialnumber",$id){
	$mdm = connectToAirwatchApi();
    $mdmurl = "https://cn556.awmdm.com/api/mdm/devices?searchby=".$searchby."&id=".$id;
    curl_setopt($mdm, CURLOPT_URL, $mdmurl);
    $mdmresult = curl_exec($mdm);
    if(!$mdmresult){
        $error =  curl_error($mdm);
        return "Failed to connect to MDM".$error;
    }else{
        $mdminfo = json_decode($mdmresult);
        if(count($mdminfo) > 1){
            $mdminfo = "Found more than one item in MDM";
        }else{
        }
    }
	return $mdminfo;
}

function discardAirwatchDevice($Udid){
	$mdm = connectToAirwatchApi();
    $mdmurl = "https://cn556.awmdm.com/api/mdm/devices?searchby=Udid&id=".$id;
    curl_setopt($mdm, CURLOPT_URL, $mdmurl);
	curl_setopt($mdm, CURLOPT_CUSTOMREQUEST, "DELETE");
    $mdmresult = curl_exec($mdm);
    if(!$mdmresult){
        $error =  curl_error($mdm);
        return false;
    }else{
		return true;
    }

}


function updateADDescriptionFromSystem($computername,$description,$mdt = 0) {
	if($mdt == 1){
		$systemuser = "MDT";
	}else{
		$systemuser = "SYSTEM";
	}
    $link = connectToAD();
    $dn = "OU=HiOA,DC=ada,DC=hioa,DC=no";
    $filter = "(cn=$computername)";
    $attributes = array('cn', 'sn', 'description');
    $result = ldap_search($link, $dn, $filter, $attributes);
    $entries = ldap_get_entries($link,$result);
    if ($entries["count"] == 1) {
        $update = array('description' => $description);
        $updatedn = $entries[0]['dn'];
        if( ldap_modify($link,$updatedn,$update) ) {
            logEvent(LOG_INFO,"AD_OPERATION: Computer '$computername' had it's description updated in Active Directory by '$systemuser'.");
            return "Beskrivelse oppdatert i Active Directory";
        }
        else {
            return "Kunne ikke oppdatere beskrivelse i Active Directory. Ukjent feil";
        }
    }
    else if ($entries["count"] < 1) {
        return  "Ingen maskinobjekter med navnet $computername finnes i Active Directory. Beskrivelse ble ikke oppdatert";
    }
    else if ($entries["count"] > 1) {
        return  "Flere maskinobjekter med navnet $computername finnes i Active Directory. Beskrivelse ble ikke oppdatert";
    }

}


function updateADDescription($computername,$description) {
	if(!isset($_SESSION['synopsis']['username'])){
		returnError("Du er ikke logget inn. Logg inn på nytt for å fullføre handlingen.");
	}
	if($_SESSION['synopsis']['username'] <= " "){
        returnError("Du er ikke logget inn. Logg inn på nytt for å fullføre handlingen.");
    }
	$link = connectToAD();
    $dn = "OU=HiOA,DC=ada,DC=hioa,DC=no";
    $filter = "(cn=$computername)";
    $attributes = array('cn', 'sn', 'description');
	$result = ldap_search($link, $dn, $filter, $attributes);
    $entries = ldap_get_entries($link,$result);
	if ($entries["count"] == 1) {
		$update = array('description' => $description);
        $updatedn = $entries[0]['dn'];
		if( ldap_modify($link,$updatedn,$update) ) {
			logEvent(LOG_INFO,"AD_OPERATION: Computer '$computername' had it's description updated in Active Directory by user '".$_SESSION['synopsis']['username']."'.");
			return "Beskrivelse oppdatert i Active Directory";
		}
		else {
			return "Kunne ikke oppdatere beskrivelse i Active Directory. Ukjent feil";
		}
	}
	else if ($entrversion1) {
		return  "Ingen maskinobjekter med navnet $computername finnes i Active Directory. Beskrivelse ble ikke oppdatert";
	}
	else if ($entries["count"] > 1) {
        return  "Flere maskinobjekter med navnet $computername finnes i Active Directory. Beskrivelse ble ikke oppdatert";
    }

}

function getSCCMProperties($computername){
	$output = Array("id" => "","model" => "Ukjent", "manufacturer" => "Ukjent","cpu" => "","ram" => "","installdate" => "");
	$sccmlink = connectToSCCMDb();
	if ($sccmlink == false){
		return $output;
	}
	$query = odbc_exec($sccmlink,"SELECT ResourceID,Model0,Manufacturer0 FROM v_GS_COMPUTER_SYSTEM WHERE Name0 = '$computername'") or returnError("Failed to connect to SCCM");
    $row = odbc_fetch_array($query);
	odbc_free_result($query);
	if(!isset($row['ResourceID'])){
		return $output;
	}
	$id = $row['ResourceID'];
	$hardwarequery = odbc_exec($sccmlink,"SELECT bios.Description0,processor.Name0,TotalPhysicalMemory0 FROM v_GS_X86_PC_MEMORY AS mem,v_GS_PROCESSOR as processor,v_GS_PC_BIOS as bios
  where bios.ResourceID = processor.ResourceID AND processor.ResourceID = mem.ResourceID AND processor.ResourceID = '$id'") or returnError("Failed to connect to SCCM");
	$cpu = $ram = $biosversion = $installdate = $osversion = "";
	while($hardwarerow = odbc_fetch_array($hardwarequery)) {
		$cpu = $hardwarerow['Name0'];
		$ram = round($hardwarerow['TotalPhysicalMemory0']/1048576) . "GB RAM";
		if(isset($hardwarerow['Description0'])){
			$biosversion = $hardwarerow['Description0'];
		}else{
			$biosversion = "N/A";
		}
	}
	$osquery = odbc_exec($sccmlink,"SELECT InstallDate0,Version0 FROM v_GS_OPERATING_SYSTEM
   WHERE ResourceID = '$id'") or returnError("Failed to connect to SCCM");
    while($osrow = odbc_fetch_array($osquery)) {
        $installdate = date('d.m.Y H:i',strtotime($osrow['InstallDate0']));
		$osversion = $osrow['Version0'];
    }

	$output = Array(
		"id" => $id,
    "model" => $row['Model0'],
		"manufacturer" => $row['Manufacturer0'],
		"cpu" => $cpu,
		"ram" => $ram,
		"installdate" => $installdate,
		"osversion" => $osversion,
		"bios" => $biosversion
   );

	return $output;
}


function getSCCMSoftware($id = '',$type = 'array'){
	if ($id == ""){
		if(isset($_GET['id'])){
			(int)$id = $_GET['id'];
			$type = 'json';
		}else{
			returnError("Ingen SCCM ID er satt. Kan ikke hente programvare for dette objektet");
		}
	}
	$sccmlink = connectToSCCMDb();
    $query = mssql_query("select ProductName0,ProductVersion0 FROM v_GS_INSTALLED_SOFTWARE_CATEGORIZED where ResourceID = $id
	AND ProductName0 NOT LIKE 'Microsoft%' ORDER BY ProductName0",	$sccmlink) or returnError(mssql_get_last_message());
    if (mssql_num_rows($query) == 0){
        $output['software'][] = Array("name" => "", "version" => "");
		$output['scantime'] = 'Ukjent/aldri';
        return $output;
    }
    while($row = mssql_fetch_array($query)) {
        $output['software'][] = Array(
          "name" => utf8_encode($row['ProductName0']),
          "version" => $row['ProductVersion0']
        );
    }
	$lastscanquery = mssql_query("SELECT LastHWScan FROM v_GS_WORKSTATION_STATUS where ResourceID = '$id'",  $sccmlink) or returnError(mssql_get_last_message());
	if (mssql_num_rows($lastscanquery) == 0){
		$output['scantime'] = 'Ukjent/aldri';
	}else{
		$row = mssql_fetch_array($lastscanquery);
		$output['scantime'] = date('d.m.Y H:i',strtotime($row['LastHWScan']));
	}

	switch($type){
		case 'array':
            return $output;
			break;
		case 'json':
			echo json_encode($output);
			break;
	}
}

function getEmployeeUserData(){
	$username = $_GET['username'];
	//Nytt
    $ch = connectToWs();
	$url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) . "synemp";
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $username);
    $result = curl_exec($ch);

    if(curl_error($ch)){
        returnError("Feil under henting av data fra BAS");
    }
    $person = json_decode($result,true);
	if(!isset($person[$username])){
		returnError("'$username' er ikke et gyldig brukernavn for ansatt");
	}
	$person = $person[$username];
	$units = array();
	foreach($person['units'] as $key => $value){
		$units[] = $key;
	}
	$reservations = array("mobile" => $person['mobilereservation'], "full" => $person['fullreservation'], "image" => $person['imagereservation']);
	$basdata = array(
		"fullname" => $person['firstname'] . " " . $person['lastname'],
		"location" => strtoupper($person['locationcode'] . "-" . $person['roomcode']),
		"units" => $units,
		"title" => $person['no_title'],
		"reservations" => $reservations,
		"other" => json_decode($result,true)
	);

	$ad = getADUserProperties($username);
	$lastlogin = getLastWindowsLogin($username);
	$admin = getAdminProperties($username,false);
	$devices = getUserDevices($username);
	$data = Array("username" => $username, "ad" => $ad, "lastlogin" => $lastlogin, "devices" => $devices, "admin" => $admin,"bas" => $basdata);
	echo json_encode($data);
}

function getADUacAttributes($inputCode){
    /**
     * http://support.microsoft.com/kb/305144
     *
     * You cannot set some of the values on a user or computer object because
     * these values can be set or reset only by the directory service.
     *
     */
	$userAccountControlFlags = array(
	16777216 => "TRUSTED_TO_AUTH_FOR_DELEGATION",
	8388608 => "PASSWORD_EXPIRED",
	4194304 => "DONT_REQ_PREAUTH",
	2097152 => "USE_DES_KEY_ONLY",
	1048576 => "NOT_DELEGATED",
	524288 => "TRUSTED_FOR_DELEGATION",
	262144 => "SMARTCARD_REQUIRED",
	131072 => "MNS_LOGON_ACCOUNT",
	65536 => "DONT_EXPIRE_PASSWORD",
	8192 => "SERVER_TRUST_ACCOUNT",
	4096 => "WORKSTATION_TRUST_ACCOUNT",
	2048 => "INTERDOMAIN_TRUST_ACCOUNT",
	512 => "NORMAL_ACCOUNT",
	256 => "TEMP_DUPLICATE_ACCOUNT",
	128 => "ENCRYPTED_TEXT_PWD_ALLOWED",
	64 => "PASSWD_CANT_CHANGE",
	32 => "PASSWD_NOTREQD",
	16 => "LOCKOUT",
	8 => "HOMEDIR_REQUIRED",
	2 => "ACCOUNTDISABLE",
	1 => "SCRIPT"
	);

	$attributes = NULL;
	while($inputCode > 0) {
        foreach($userAccountControlFlags as $flag => $flagName) {
            $temp = $inputCode-$flag;
            if($temp>0) {
                $attributes[$userAccountControlFlags[$flag]] = $flag;
                $inputCode = $temp;
            }
            if($temp==0) {
                if(isset($userAccountControlFlags[$inputCode])) {
                    $attributes[$userAccountControlFlags[$inputCode]] = $inputCode;
                }
                $inputCode = $temp;
            }
        }
	}
	return $attributes;
}


function getADUserProperties($username) {
    $link = connectToAD();
    $dn = "OU=Managed,OU=HiOA,DC=ada,DC=hioa,DC=no";
    $filter = "(&(objectClass=user)(cn=$username))";
    $attributes = array('cn', 'sn', 'description','displayname','memberof','pwdlastset','badpasswordtime','useraccountcontrol','homedirectory','thumbnailphoto');
    $result = ldap_search($link, $dn, $filter, $attributes);
    $entries = ldap_get_entries($link,$result);
    if ($entries["count"] == 1){
        $grouplist = Array();
        if (isset($entries[0]['memberof']) ) {
            foreach($entries[0]['memberof'] as $groups) {
                $groupname = ldap_explode_dn($groups,1);
                if ($groupname == null)
                    continue;
                $grouplist[] = $groupname[0];
            }
        }
		if(isset($entries[0]['badpasswordtime'])){
			$badpwtime = $entries[0]['badpasswordtime'][0];
			$winsecs = (int)($badpwtime / 10000000); // divide by 10 000 000 to get seconds
			$unixtime = ($winsecs - 11644473600); // 1.1.1600 -> 1.1.1970 difference in seconds
			$badpwtime = date('d.m.Y H:i',$unixtime);
		}else{
			$badpwtime = "Ukjent";
		}
		if(isset($entries[0]['pwdlastset'])){
            $pwdlastset = $entries[0]['pwdlastset'][0];
            $winsecs = (int)($pwdlastset / 10000000); // divide by 10 000 000 to get seconds
            $unixtime = ($winsecs - 11644473600); // 1.1.1600 -> 1.1.1970 difference in seconds
            $pwdlastset = date('d.m.Y H:i',$unixtime);
        }else{
            $pwdlastset = "Ukjent";
        }

		$uac = getADUacAttributes($entries[0]['useraccountcontrol'][0]);
		if(!isset($uac["ACCOUNTDISABLE"])){
			$active = "true";
		}else{
			$active = "false";
		}
		if(!isset($uac["LOCKOUT"])){
            $locked = "false";
        }else{
            $locked = "true";
        }

		if(isset($entries[0]['thumbnailphoto'])){
			$thumbnail = base64_encode($entries[0]['thumbnailphoto'][0]);
		}else{
			$thumbnail = "";
		}

		if(isset($entries[0]['homedirectory'][0])){
			$homedirectory = $entries[0]['homedirectory'][0];
		}else{
			$homedirectory = "Ingen";
		}
        $output = Array(
                "displayname" => $entries[0]['displayname'][0],
                "thumbnail" => $thumbnail,
                "locked" => $locked,
                "active" => $active,
          "exists" => true,
                "badpw" => $badpwtime,
                "pwdlastset" => $pwdlastset,
          "dn" => $entries[0]['dn'],
                "home" => $homedirectory,
          "groups" => $grouplist
        );
    }
    else {
        $output = Array("exists" => false,"dn" => "","groups" => "");
    }
    @ldap_unbind($link);
    return $output;
}

function getADProperties($computername) {
	$link = connectToAD();
    $dn = "OU=HiOA,DC=ada,DC=hioa,DC=no";
    $filter = "(cn=$computername)";
    $attributes = array('cn', 'sn', 'description','memberof','ms-FVE-RecoveryInformation','ms-Mcs-AdmPwd');
    $result = ldap_search($link, $dn, $filter, $attributes);
	$entries = ldap_get_entries($link,$result);
	if ($entries["count"] == 1){
		$grouplist = Array();
		if (isset($entries[0]['memberof']) ) {
			foreach($entries[0]['memberof'] as $groups) {
				$groupname = ldap_explode_dn($groups,1);
				if ($groupname == null)
					continue;
				$grouplist[] = $groupname[0];
            }
		}
		if (getOtpLoginStatus() == false){
			$recoverykey = "Logg inn med engangskode";
			$adminpwd = "Logg inn med engangskode";
		}else{
			$recoverykey = getRecoveryKey($entries[0]['dn']);
			logEvent(LOG_INFO,"SYN_OPERATION: Computer '$computername' was viewed with sensitive details by user '".$_SESSION['synopsis']['username'].".");
			if (isset($entries[0]['ms-mcs-admpwd'])){
				$adminpwd = $entries[0]['ms-mcs-admpwd'][0];
			}else{
				$adminpwd = "";
			}
		}

		$output = Array(
			"exists" => true,
			"dn" => $entries[0]['dn'],
			"groups" => $grouplist,
			"recoverykey" => $recoverykey,
			"adminpassword" => $adminpwd
		);
	}
	else {
		$output = Array("exists" => false,"dn" => "","groups" => "","recoverykey" => "N/A","adminpassword" => "N/A");
	}
	@ldap_unbind($link);
	return $output;
}

function getRecoveryKey($dn) {
	$output = "";
	$link = connectToAD();
    $filter = "(&(objectClass=msFVE-RecoveryInformation))";
	$attributes = array('msfve-recoverypassword','whencreated','cn');
	$result = ldap_search($link, $dn, $filter, $attributes);
    $entries = ldap_get_entries($link,$result);
    if ($entries["count"] >= 1){
		$maxdate = "";
		foreach($entries as $entry){
			if (isset($entry['msfve-recoverypassword']) ) {
				$date = strtotime(substr($entry['whencreated'][0],0,-5));
				if($date > $maxdate){
					$maxdate = $date;
					$output =  "Dato: " . date('d.m.Y H:i', $date) . "<br />";
                    $output .= "GUID: " . substr($entry['cn'][0], -38) . "<br />";
                    $output .= "--------------------------</br>";
					$output .= $entry['msfve-recoverypassword'][0];
				}
            }
		}
		return $output;
	}
	else {
		return "Fant ikke oppføring";
	}
}


function moveADObject($computername = "", $ou = "") {
	if ($computername == ""){
		$computername = $_POST['computername'];
	}
    if ($ou == ""){
		$ou = $_POST['ou'];
	}
    $link = connectToAD();
	$dn = "OU=HiOA,DC=ada,DC=hioa,DC=no";
    $filter = "(CN=$computername)";
    $attributes = array('cn');
    $result = ldap_search($link, $dn, $filter, $attributes);
    $entries = ldap_get_entries($link,$result);
    if ($entries["count"] == 1){
		if(!ldap_rename( $link, $entries[0]['dn'], "CN=$computername", $ou, TRUE)) {
			returnError(ldap_error($link) . " bla" .$ou);
		}
		else {
			$ou = ldap_explode_dn($ou,1);
			logEvent(LOG_INFO,"AD_OPERATION: Computer '$computername' was moved to '".$ou[0]."' in Active Directory by user '".$_SESSION['synopsis']['username'].".");
			echo "Objektet ble flyttet til $ou[0].";
		}
	}
}

function findADObject($name) {
	$link = connectToAD();
    $dn = "OU=HiOA,DC=ada,DC=hioa,DC=no";
    $filter = "(cn=$name)";
    $attributes = array('cn');
    $result = ldap_search($link, $dn, $filter, $attributes);
    $entries = ldap_get_entries($link,$result);
	return $entries;
}

function deleteRecoveryKey($dn){
	$link = connectToAD();
	$filter = "(&(objectClass=msFVE-RecoveryInformation))";
    $attributes = array('msfve-recoverypassword');
    $result = ldap_search($link, $dn, $filter, $attributes);
    $entries = ldap_get_entries($link,$result);
	if ($entries["count"] == 0){
		return;
	}
	foreach($entries as $entry){
		$entrydn = $entry['dn'];
		@ldap_delete($link,$entrydn);
	}

}

function deleteADObject($name) {
	$entries = findADObject($name);
    if ($entries["count"] == 1){
		$link = connectToAD();
		$dn = $entries[0]['dn'];
		deleteRecoveryKey($dn);
		if ( !ldap_delete($link,$dn)) {
			returnError("Kunne ikke slette objektet fra Active Directory.\n\n(Dette påvirker ikke sletting fra databasen.)");
		}else{
			logEvent(LOG_INFO,"AD_OPERATION: Computer '$name' was deleted from Active Directory by user '".$_SESSION['synopsis']['username']."'.");
		}
	}
	else if ($entries["count"] > 1){
        returnError("Fant flere objekter som passet med dette navnet. Slett objektet manuelt i Active Directory.");
	}
	else{
		returnError("Fant ingen objekter som passet med dette navnet i Active Directory.");
	}

}

function getOUList($elementname = "ou") {
	$link = connectToAD();
	$output = "<select class='form-control' name='$elementname'><option value=''></option><optgroup label='Tilsatt (Windows 10)'>";
    $dn = "OU=Employees,OU=Computers (Windows 10),OU=HiOA,DC=ada,DC=hioa,DC=no";
    $attributes = array("ou");
    $sr = ldap_search($link, $dn, "ou=*", $attributes);
    $info = ldap_get_entries($link, $sr);
    for ($i=0; $i < $info["count"]; $i++) {
        $output .= "<option value='".$info[$i]["dn"]."'>".$info[$i]["ou"][0]."</option>";
    }
    $output .= "<optgroup label='Student (Windows 10)'>";
    $dn = "OU=Students,OU=Computers (Windows 10),OU=HiOA,DC=ada,DC=hioa,DC=no";
    $attributes = array("ou");
    $sr = ldap_search($link, $dn, "ou=*", $attributes);
    $info = ldap_get_entries($link, $sr);
    for ($i=0; $i < $info["count"]; $i++) {
        $output .= "<option value='".$info[$i]["dn"]."'>".$info[$i]["ou"][0]."</option>";
    }
	$output .= "<optgroup label='Kiosk (Windows 10)'>";
    $dn = "OU=Kiosk,OU=Computers (Windows 10),OU=HiOA,DC=ada,DC=hioa,DC=no";
    $attributes = array("ou");
    $sr = ldap_search($link, $dn, "ou=*", $attributes);
    $info = ldap_get_entries($link, $sr);
    for ($i=0; $i < $info["count"]; $i++) {
        $output .= "<option value='".$info[$i]["dn"]."'>".$info[$i]["ou"][0]."</option>";
    }

	$output .= "<optgroup label='Tilsatt'>";
    $dn = "OU=Employees,OU=Computers,OU=HiOA,DC=ada,DC=hioa,DC=no";
	$attributes = array("ou");
	$sr = ldap_search($link, $dn, "ou=*", $attributes);
	$info = ldap_get_entries($link, $sr);
	for ($i=0; $i < $info["count"]; $i++) {
	    $output .= "<option value='".$info[$i]["dn"]."'>".$info[$i]["ou"][0]."</option>";
	}
	$output .= "<optgroup label='Student'>";
	$dn = "OU=Students,OU=Computers,OU=HiOA,DC=ada,DC=hioa,DC=no";
    $attributes = array("ou");
    $sr = ldap_search($link, $dn, "ou=*", $attributes);
    $info = ldap_get_entries($link, $sr);
    for ($i=0; $i < $info["count"]; $i++) {
        $output .= "<option value='".$info[$i]["dn"]."'>".$info[$i]["ou"][0]."</option>";
    }
	$output .= "<optgroup label='Server'>";
    $dn = "OU=Servers,OU=HiOA,DC=ada,DC=hioa,DC=no";
    $attributes = array("ou");
    $sr = ldap_search($link, $dn, "ou=*", $attributes);
    $info = ldap_get_entries($link, $sr);
    for ($i=0; $i < $info["count"]; $i++) {
        $output .= "<option value='".$info[$i]["dn"]."'>".$info[$i]["ou"][0]."</option>";
    }

	$output .= "</select>";
	echo $output;
}

function encryptDecrypt($action, $string) {
    $output = false;

    $encrypt_method = "AES-256-CBC";
    $secret_key = 'chu9Ohsh0Wah9Yeak6ahw$ei6lob>utaiph2Il]iebei3ahz0Zeroh9Shaejee';
    $secret_iv = 'bie4LohGh9isheeXeih9eroh9ShaejeeR8uh8aih';

    // hash
    $key = hash('sha256', $secret_key);

    // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
    $iv = substr(hash('sha256', $secret_iv), 0, 16);

    if( $action == 'encrypt' ) {
        $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
        $output = base64_encode($output);
    }
    else if( $action == 'decrypt' ){
        $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
    }

    return $output;
}

function getSecretKey($username){
	$dblink = connectToSysDb();
	$result = mysqli_query($dblink,"SELECT otpkey FROM synopsis_users WHERE username = '".$username."'")or returnError(mysqli_error($dblink));
	$row = mysqli_fetch_array($result);
	if (empty($row['otpkey'])){
		return "";
	}else {
		$key = encryptDecrypt("decrypt",$row['otpkey']);
		return $key;
	}
}

function setSecretKey($username){
	$key = Google2FA::generate_secret_key();
	$key = encryptDecrypt("encrypt",$key);
	$dblink = connectToSysDb();
    $result = mysqli_query($dblink,"UPDATE synopsis_users SET otpkey = '$key' WHERE username = '".$username."'")or returnError(mysqli_error($dblink));
}

function getOtpStatus($username){
	$dblink = connectToSysDb();
	$result = mysqli_query($dblink,"SELECT requireotp FROM synopsis_users WHERE username = '".$username."'")or returnError(mysqli_error($dblink));
    $row = mysqli_fetch_array($result);
	return $row['requireotp'];
	mysqli_close($dblink);
}

function setOtpStatus($username = '',$status = '' ){
	if (empty($username)){
		$username = $_SESSION['synopsis']['username'];
	}
	if (empty($status)){
        (int)$status = $_GET['status'];
    }
	$dblink = connectToSysDb();
	$result = mysqli_query($dblink,"UPDATE synopsis_users SET requireotp = $status WHERE username = '".$username."'")or returnError(mysqli_error($dblink));
	mysqli_close($dblink);
	return $status;
}

function getOtpLoginStatus(){
	if (!isset($_SESSION['synopsis']['otp-time'])){
		return false;
	}else{
		if( ($_SESSION['synopsis']['otp'] == true) && ($_SESSION['synopsis']['otp-time'] > time()) ){
			return true;
		}else{
			return false;
		}
	}
}

function convertPgArray($pgArray){
	$pgStr = trim($pgArray,"{}");
	$elmts = explode(",",$pgStr);
	return $elmts;
}


function logEvent($priority,$message){
	openlog("Synopsis", LOG_NDELAY, LOG_LOCAL3);
	syslog($priority, $message);
	closelog();

}

function returnError($error,$type = "html"){
    header('Content-Type: text/plain; charset=utf-8');
    header('HTTP/1.1 500 '.  $error,true);
	if ($type == "html"){
        die("$error");
	}else{
		die($error);
	}
}

?>
