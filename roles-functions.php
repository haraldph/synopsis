<?php

function addEditUserRoleSystem(){
  $link = connectToSysDb();
  foreach($_POST as $key=>$value) {
    $input[$key]=mysqli_real_escape_string($link,$value);
  }
  if($input['description'] <= ""){
    returnError("Oppgi en beskrivelse av systemet");
  }
  if($input['name'] <= ""){
    returnError("Oppgi et systemnavn");
  }
  if(is_numeric($input['id'])){
    mysqli_query($link,"UPDATE synopsis_roles_systems SET name='".$input['name']."', description = '".$input['description']."' WHERE id = '".$input['id']."'")or returnError("Kunne ikke oppdatere systemet");
		logEvent(LOG_INFO,"SYN_OPERATION: Update role system object '".$input['id']."'/'".$input['name']."' performed by '".$_SESSION['synopsis']['username']."'.");
  }else{
    mysqli_query($link,"INSERT INTO synopsis_roles_systems (name,description) VALUES('".$input['name']."','".$input['description']."')")or returnError("Kunne ikke lagre nytt system");
		logEvent(LOG_INFO,"SYN_OPERATION: Update role system object '".$input['id']."'/'".$input['name']."' performed by '".$_SESSION['synopsis']['username']."'.");
  }
}

function getUserRoleSystems($outputtype = 'table'){
  $link = connectToSysDb();
  $result = mysqli_query($link,"SELECT id,name,description FROM synopsis_roles_systems")or returnError("Kunne ikke laste systemer");
	switch($outputtype){
	case "table":
		$output = "
		  <table class='table table-hover'>
  			<thead>
      		<tr>
        		<th><b>Systemnavn</b></th><th><b>Beskrivelse</b></th>
	        </tr>
  	    </thead>
    	  <tbody>";	
		while ($row = mysqli_fetch_array($result)) {
		  $output .= "<tr><td>" . $row['name'] . "</td><td>" . $row['description'] . "</td></tr>";
	  }
		$output .= "</tbody></table>";
		break;
	case "select":
		$output = "<select name='role-systems' class='form-control'>";
		while ($row = mysqli_fetch_array($result)) {
      $output .= "<option value='".$row['id']."'>" . $row['name'] . "</option>";
    }
    $output .= "</select>";
    break;
	}
	mysqli_free_result($result);
  mysqli_close($link);
	echo $output;
}


?>
