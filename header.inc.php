<?php
require("functions.php");
if(!isset($_SESSION["synopsis"])){
	$redirect = "https://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
  header("location: /login.php?redirect=$redirect");
  die();
}
else{
$basicuser = $poweruser = $adminuser = $delegation = false;
  if ($_SESSION["synopsis"]['userlevel'] >= 1){
    $basicuser = true;
    if ($_SESSION["synopsis"]['delegation'] == 1)
        $delegation = $_SESSION["synopsis"]['delegation'];
    if ($_SESSION["synopsis"]['userlevel'] >= 5)
      $poweruser = true;
    if ($_SESSION["synopsis"]['userlevel'] == 9)
      $adminuser = true;
  }else{
    header("location: forbidden.php");
    die();
  }
  if(getOtpStatus($_SESSION["synopsis"]['username']) == "1"){
    if ($_SESSION["synopsis"]["otp"] == "false"){
      header("location: otp-login.php");
      die();
    }
  }

}

?>

<!DOCTYPE html>
<html lang="en">

    <head>

        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <meta name="description" content="">
        <meta name="author" content="">

        <title>Synopsis</title>

        <!-- Bootstrap core CSS -->
        <link href="/vendor/twbs/bootstrap/dist/css/bootstrap.min.css" rel="stylesheet">
		    <link href="/css/typeaheadjs.css" rel="stylesheet" />
		    <!-- Custom styles for this template -->
		    <link href="https://use.fontawesome.com/releases/v5.6.3/css/all.css" rel="stylesheet">
		    <link rel="stylesheet" type="text/css" href="/vendor/datatables/datatables/media/css/dataTables.bootstrap4.min.css"/>
        <link href="/css/sidebar.css" rel="stylesheet">
        <link href="/css/style.css" rel="stylesheet">

    </head>

    <body>
    <div class="navbar navbar-inverse bg-inverse">
    <!--	<div class="container d-flex justify-content-between"> -->
    <h3 id="logo"> syn•op•sis</h3>
	    <div class="float-right">
		    <div class="dropdown">
			    <button class="btn-sm btn-light-outline dropdown-toggle" type="button" id="dropdownMenuButton" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
			    <img id="userimage" src="data:image/jpeg;base64,<?php echo base64_encode($_SESSION['synopsis']['picture']); ?>" /> <?php echo $_SESSION['synopsis']['firstname'];?>
			    </button>
			    <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">
			    <a class="dropdown-item" href="/login.php?logout"><i class="fa fa-fw fa-sign-out-alt"></i> Logg ut</a>
				    <a class="dropdown-item" href="/otp-login.php"><i class="fa fa-fw fa-lock"></i> To-faktor</a>
			    <a class="dropdown-item" href="/myaccount.php"><i class="fa fa-fw fa-user"></i> Min konto</a>
			    </div>
		    </div>
	    </div>
    <!--	</div> -->
    </div>
    <div class="container-fluid">
        <div class="row d-flex d-md-block flex-nowrap wrapper">
            <div class="col-md-2 float-left col-1 pl-0 pr-0 collapse width show" id="sidebar">
                    <div class="list-group border-0 card text-center text-md-left">
								
								    <!--
                    <a href="#menu1" class="list-group-item d-inline-block collapsed" data-toggle="collapse" data-parent="#sidebar" aria-expanded="false"><i class="fa fa-dashboard"></i> <span class="d-none d-md-inline">Item 1</span> </a>
                    <div class="collapse" id="menu1">
                        <a href="#menu1sub1" class="list-group-item" data-toggle="collapse" aria-expanded="false">Subitem 1 </a>
                        <div class="collapse" id="menu1sub1">
                            <a href="#" class="list-group-item" data-parent="#menu1sub1">Subitem 1 a</a>
                            <a href="#" class="list-group-item" data-parent="#menu1sub1">Subitem 2 b</a>
                            <a href="#menu1sub1sub1" class="list-group-item" data-toggle="collapse" aria-expanded="false">Subitem 3 c </a>
                            <div class="collapse" id="menu1sub1sub1">
                                <a href="#" class="list-group-item" data-parent="#menu1sub1sub1">Subitem 3 c.1</a>
                                <a href="#" class="list-group-item" data-parent="#menu1sub1sub1">Subitem 3 c.2</a>
                            </div>
                            <a href="#" class="list-group-item" data-parent="#menu1sub1">Subitem 4 d</a>
                            <a href="#menu1sub1sub2" class="list-group-item" data-toggle="collapse" aria-expanded="false">Subitem 5 e </a>
                            <div class="collapse" id="menu1sub1sub2">
                                <a href="#" class="list-group-item" data-parent="#menu1sub1sub2">Subitem 5 e.1</a>
                                <a href="#" class="list-group-item" data-parent="#menu1sub1sub2">Subitem 5 e.2</a>
                            </div>
                        </div>
                        <a href="#" class="list-group-item" data-parent="#menu1">Subitem 2</a>
                        <a href="#" class="list-group-item" data-parent="#menu1">Subitem 3</a>
                    </div>
                    <a href="#" class="list-group-item d-inline-block collapsed" data-parent="#sidebar"><i class="fa fa-film"></i> <span class="d-none d-md-inline">Item 2</span></a>
								    -->
								    <?php $currentpage = basename($_SERVER['PHP_SELF']);
									    if($currentpage == 'index.php' || $currentpage == "mac-search.php" || $currentpage == "mobile-search.php" || $currentpage == "linux-search.php"){
										    $searcharia = "true";
										    $searchclass = "collapse show";
									    }else{
										    $searcharia = "false";
                        $searchclass = "collapse";
									    }
									    if(substr($currentpage,0,6) == "roles-"){
								 		    $rolearia = "true";
                        $roleclass = "collapse show";
                      }else{
                        $rolearia = "false";
                        $roleclass = "collapse";
                      }
									    if(substr($currentpage,0,7) == "system-"){
                        $systemaria = "true";
                        $systemclass = "collapse show";
                      }else{
                        $systemaria = "false";
                        $systemclass = "collapse";
									    }
								    ?>								
								    <a href="#menu1" class="list-group-item d-inline-block" data-toggle="collapse" data-parent="#sidebar" aria-expanded="<?php echo $searcharia; ?>"><i class="fa fa-fw fa-lg fa-search"></i> <span class="d-none d-md-inline">Enhetssøk</span></a>
                    <div class="<?php echo $searchclass; ?>" id="menu1">
                        <a href="/index.php" class="list-group-item" data-parent="#menu1"><i class="fab fa-lg f-fw fa-windows"></i>Windows</a>
										    <a href="/mac-search.php" class="list-group-item" data-parent="#menu1"><i class="fab fa-lg f-fw fa-apple"></i>MacOS</a>
                        <a href="/mobile-search.php" class="list-group-item" data-parent="#menu1"><i class="fa fa-lg fa-fw fa-mobile"></i>Mobile enheter</a>
										    <a href="/linux-search.php" class="list-group-item" data-parent="#menu1"><i class="fab fa-lg fa-fw fa-linux"></i>Linux</a>
                    </div>
								
                    <a href="/new.php" class="list-group-item d-inline-block collapsed" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-plus"></i> <span class="d-none d-md-inline">Registrering</span></a>
                    <a href="/users.php" class="list-group-item d-inline-block collapsed" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-id-card"></i> <span class="d-none d-md-inline">Brukeradm.</span></a>
								    <a href="/reports.php" class="list-group-item d-inline-block collapsed" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-chart-bar"></i> <span class="d-none d-md-inline">Rapporter</span></a>
								    <a href="/discarded.php" class="list-group-item d-inline-block collapsed" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-trash"></i> <span class="d-none d-md-inline">Kassering</span></a>
								    <a href="/wifiguest.php" class="list-group-item d-inline-block collapsed" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-wifi"></i> <span class="d-none d-md-inline">Trådløs-konto</span></a>
    <!--
								    <a href="#menu2" class="list-group-item d-inline-block collapsed" data-toggle="collapse" data-parent="#sidebar" aria-expanded="<?php echo $rolearia; ?>"><i class="fa fa-fw fa-lg fa-user-tag"></i> <span class="d-none d-md-inline">Brukerroller</span></a>
									    <div class="<?php echo $roleclass; ?>" id="menu2">
										    <a href="/roles-systems.php" class="list-group-item" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-box-open"></i> <span class="d-none d-md-inline">Systemer</span></a>
										    <a href="/roles-admin.php" class="list-group-item" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-tag"></i> <span class="d-none d-md-inline">Roller</span></a>
									    </div>
    -->
                    <?php if($adminuser == true){
								    echo '
								    <a href="#menu3" class="list-group-item d-inline-block collapsed" data-toggle="collapse" data-parent="#sidebar" aria-expanded="'.$systemaria.'"><i class="fa fa-fw fa-lg fa-cogs"></i> <span class="d-none d-md-inline">Systeminst.</span></a>
                	    <div class="'.$systemclass.'" id="menu3">
										    <a href="/system-users.php" class="list-group-item" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-users"></i> <span class="d-none d-md-inline">Brukere</span></a>
										    <a href="/system-settings.php" class="list-group-item" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-wrench"></i> <span class="d-none d-md-inline">Innstillinger</span></a>
										    <a href="/system-logviewer.php" class="list-group-item" data-parent="#sidebar"><i class="fa fa-lg fa-fw fa-file-alt"></i> <span class="d-none d-md-inline">Logg</span></a>
									    </div>';
								    }
								    ?>
                </div>
            </div>

    </body>
</html>