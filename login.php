<?php
session_start();
if(isset($_GET['logout'])){
	session_destroy();
}
if(isset($_GET['redirect'])){
  $redirect = $_GET['redirect'];
}else{
	$redirect = "";
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
		<link href="//maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" rel="stylesheet" />
    <!-- Custom styles for this template -->
		<link href="css/style.css" rel="stylesheet">

</head>

<body>
<div class="navbar navbar-inverse bg-inverse">
<!--	<div class="container d-flex justify-content-between"> -->
  	<h3 style="color: rgba(234,190,0,1);"> syn•op•sis</h3>
<!--	</div> -->
</div>
<div class="container pt-5">
	<form action="auth.php" method="post" style="max-width: 500px; margin: 0 auto;">
        <h2 class="text-center display-4 mb-3">logg inn</h2>
				<div class="input-group mb-2">
					<div class="input-group-prepend">
	          <span class="input-group-text" id="basic-addon1"><i class="fa fa-fw fa-user"></i></span>
					</div>
          <input type="text" id="username" name="username" autofocus="" required="" class="form-control" placeholder="Brukernavn">
        </div>
				<div class="input-group mb-2">
					<div class="input-group-prepend">
	          <span class="input-group-text" id="basic-addon1"><i class="fa fa-fw fa-key"></i></span>
					</div>
          <input type="password" id="password" name="password" required="" class="form-control" placeholder="Passord">
        </div>
				<hr>
				<input type="text" value="<?php echo $redirect; ?>" class="invisible" name="redirect" />
        <button class="btn btn-lg btn-dark btn-block" type="submit"><i class="fa fa-sign-in"></i> Logg inn</button>
      </form>
</div>
  <!-- Bootstrap core JavaScript -->
  <script src="/vendor/components/jquery/jquery.min.js"></script>
  <script src="/vendor/twbs/bootstrap/dist/js/bootstrap.min.js"></script>
  <script src="/js/script.js"></script>

</body>

</html>

