<?php

function connectToSysDb(){
  $link = mysqli_connect("localhost", "synopsis", "SECRET", "synopsis");
  if (mysqli_connect_errno()) {
    die(mysqli_connect_error());
  }else{
    return $link;
  }
}

function connectToWs(){
	$dev = false;
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	if($dev){
		curl_setopt($ch, CURLOPT_URL, "https://pybas-dev.hioa.no:3222/");
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("pybaws:SECRET","Content-Type: application/json"));
    curl_setopt($ch, CURLOPT_POST, true);
	}
	else{
		curl_setopt($ch, CURLOPT_URL, "https://ws.hioa.no/");
	  curl_setopt($ch,CURLOPT_CAINFO, "/etc/pki/ca-trust/source/anchors/wshioano.crt");
  	curl_setopt($ch, CURLOPT_HTTPHEADER, array("pybaws:SECRET","Content-Type: application/json"));
	  curl_setopt($ch, CURLOPT_POST, true);
	}
  return $ch;
}

function connectToPybasDb() {
  $link = pg_connect("host=pybasql.hio.no dbname=pybas user=synopsis password=SECRET sslmode=require");
  if (!$link) {
    returnError("Kunne ikke koble til PyBAS.");
  }
  else {
    return $link;
  }
}


function connectToMdtDb(){
  $link = odbc_connect('MDT', 'synopsis', 'SECRET');
  if ($link == FALSE){
    returnError("Kunne ikke koble til MDT-databasen".odbc_errormsg());
  }
  //mssql_select_db('MDT2010', $link_mssql);
  return $link;
}


function connectToSCCMDb(){
  $link_sccm = odbc_connect('SCCM', 'Synopsis', 'SECRET');
  if (!$link_sccm){
    return false;
    die;
  }
  return $link_sccm;
}


function pingDC($host){
  $op = @fsockopen($host, 636, $errno, $errstr, 1);
  if (!$op){
    return 0;
  }
  else {
    fclose($op);
    return 1;
  }
}

function connectToAD(){
    $server = "";
    $dclist = array("dc-1.ada.hioa.no","dc-2.ada.hioa.no");
    //$dclist = array("dc-p-2.ada.hioa.no");
    foreach ($dclist as $k => $dc){
      if (pingDC($dc) == 1){
        $server = $dc;
        break;
      }
    }
    if ($server == ""){
      die("Could not connect to Active Directory");
    }
    $server = "ldaps://$server";
    //$server = "ldaps://dc-p-2.ada.hioa.no";
    $user = "synopsis@ada.hioa.no";
    $password = "SECRET";
    $ad = ldap_connect($server) or die("Could not connect to {$server}");
    ldap_set_option($ad, LDAP_OPT_PROTOCOL_VERSION, 3) ;
    ldap_bind($ad, $user, $password) or die("Could not bind to Active Directory");
    return $ad;
}

function connectToMunkiApi(){
	$data = array("login" => "synopsis","password" => "SECRET");
   $ch = curl_init();
   curl_setopt($ch, CURLOPT_URL, 'https://report.munki.oslomet.no/index.php?/auth/login');
   curl_setopt($ch, CURLOPT_POST, true);
   curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
   curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
   curl_setopt($ch, CURLOPT_COOKIESESSION, true);
   curl_setopt($ch, CURLOPT_COOKIEJAR, 'munki-report-cookie'); 
   $result = curl_exec($ch); 
   return $ch;
}

function connectToAirwatchApi(){
  $username = "synopsis";
	$password = "SECRET";
  $ch = curl_init();
	curl_setopt($ch, CURLOPT_HTTPHEADER, array("aw-tenant-code:4Zp3cDl+DEl7hv2UVCaqVYLDCBs6b6RUTxzvtwfzDe8=","Content-Type: application/json"));
  curl_setopt($ch, CURLOPT_URL, 'https://cn556.awmdm.com/api/mdm/devices');
	curl_setopt($ch, CURLOPT_PROXY, "proxy.hioa.no:3128");
	curl_setopt($ch, CURLOPT_USERPWD, $username . ":" . $password); 
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  return $ch;
}


function connectToMunki(){
  $password = "SECRET";
  $link = mysqli_init();
  if (!$link) {
    die('mysqli_init failed');
  }
  //mysqli_ssl_set($link,NULL,NULL,"/etc/pki/tls/certs/chain-synopsis.hioa.no.pem",NULL,NULL);
  mysqli_real_connect($link, "munki.oslomet.no", "synopsis", "$password", "munkireport");
  if (mysqli_connect_errno()) {
    die(mysqli_connect_error());
  }else{
    mysqli_set_charset($link, "utf8");
    return $link;
  }

}


