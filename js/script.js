
function autoFormatMac(field) {
  var last = field.value.substring( field.value.lastIndexOf(":") + 1, field.value.length);
  if (last.length >= 2)
    field.value = field.value + ":";
  if (field.value.length > 17)
     field.value = field.value.substring(0, 17);

}

function deviceSearch(searchtype){
  $('#search-results').html("Søker etter enheter... <i class='fa fa-circle-o-notch fa-spin fa-lg fa-fw'></i>");
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec="+searchtype+"Search",
    data: $("#form-"+searchtype+"-search").serialize(),
    success: function(data) {
      if (data.indexOf("<table") != -1){
        $("#search-results").html(data);
				$("#search-results > table").DataTable({
			    "paging": false,
					"language": {
						url : '/vendor/datatables/norwegian.json'
					}
				});
      }
      else{
        window.location = 'login.php?logout=true';
      }
    },
    error: function(msg) {
      $("#search-results").html('<div class="alert alert-warning" role="alert"><i class="fa fa-warning"></i> '+ msg.responseText +'</div>');
    }

  });

}

function getNetworkStatus(macaddress,type){
	var element = '#network-status-'+type;
  $(element).html("<i class='fas fa-circle-notch fa-spin fa-fw'></i>");
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=getNetworkStatus&mac="+macaddress,
    success: function(data) {
				data = JSON.parse(data);
				if(data['count'] == 1){
					$(element).attr('title', "Aktiv siden "+data['results'][0]['start_time']);
	        $(element).html("<i class='blink fas fa-wifi fa-fw'></i>");
				}else{
					$(element).attr('title', "Ikke tilkoblet. Kan være tilkoblet på Wifi.");
					$(element).html("<i class='far fa-question-circle fa-fw'></i>");
				}
    },
    error: function(msg) {
			$(element).attr('title', "Ukjent status");
      $(element).html("<i class='far fa-question-circle fa-fw'></i>");
    }

  });
}


function getUserData(type){
	if(type == "employee"){
		var exec = "getEmployeeUserData";
	}else if(type == "student"){
		var exec = "getStudentUserData";
	}
  $('#user-results').html("Henter data... <i class='fas fa-circle-notch fa-spin fa-lg fa-fw'></i>");
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec="+exec,
    data: $("#form-"+type+"-search").serialize(),
    success: function(data) {
				populateUserData(type,data);
				$("#user-results").html("");
    },
    error: function(msg) {
      $("#user-results").html('<div class="alert alert-warning" role="alert"><i class="fa fa-warning"></i> '+ msg.responseText +'</div>');
    }

  });

}

function populateUserData(type,data){
	$("#ad").hide();
	data = JSON.parse(data);
	var username = data['username'];
	history.pushState(null,null,"users.php?user="+username);
	//General
	if(data['ad']['thumbnail']){
		$("#user-thumbnail").attr("src","data:image/jpeg;base64," + data['ad']['thumbnail']);
	}else{
		$("#user-thumbnail").attr("src","");
	}
  $("#bas-title").text(data['bas']['title']);
	$("#bas-location").text(data['bas']['location']);
	$("#bas-units").text(data['bas']['units']);
	
	var reservations = "";
	if(data['bas']['reservations']['image']){
    reservations += "BILDE,";
  }
	if(data['bas']['reservations']['mobile']){
		reservations += "MOBIL,";
	}
	if(data['bas']['reservations']['full']){
    reservations += "FULL";
  }
	if(reservations == ""){
		reservations = "Ingen";
	}
	$("#bas-reservations").text(reservations);
	if(data['lastlogin'][0]){
		$("#user-lastlogin").html("<a href='index.php?device="+data['lastlogin'][0]['id']+"'>"+data['lastlogin'][0]['name']+"</a>");
	}
	$("#general").css('display', 'flex');	
	//AD Data
	if(data['ad']['exists'] == "false"){
		$("#ad-error").html("<h5 class='text-danger'>Kunne ikke hente data fra Active Directory. Brukeren eksisterer kanskje ikke der.</h5> ");
		$("#ad-user-container").hide();
		$("#ad-error").show();
	}else{
		$("#ad-error").hide();
		$("#ad-groups-container #ad-user-container").show();
	}
	/*
	var grplist = "";
	$.each(data['ad']['groups'], function(i, item) {
    grplist += "<li class='list-group-item pt-1 pb-1'>"+item+"</li>";
	});
	$("#ad-groups").html(grplist);
	*/
	$("#user-displayname").text(data['bas']['fullname']);
	if(data['ad']['locked'] == "true"){
		var locked = "<i class='text-danger fa fa-locked'></i>";
	}else{
		var locked = "<i class='text-success fa fa-unlock'></i>";
	}
	if(data['ad']['active'] == "true"){
		$("#ad-status").html("<span class='text-success'>Aktiv</span> "+locked);
	}else{
		$("#ad-status").html("<span class='text-danger'>Deaktivert</span> "+locked);
	}
	$("#ad-badpw, #ad-pwdlastset, #ad-home").html("Ukjent");
	$("#ad-badpw").html(data['ad']['badpw']);
	$("#ad-pwdlastset").html(data['ad']['pwdlastset']);
	$("#ad-home").html(data['ad']['home']);
	$("#ata-link").attr('href','https://ata-mgmt.ada.hioa.no/search?search='+ data['username'] + '&filter=user');
	$("#ad").css('display', 'flex');

	//Admin data
	if(data['admin'][username]){
		var admin = data['admin'][username];
		if(admin['classroomadmin'] == true){
			$("#admin-status").html("Klasseromadministrator");
		}else if(admin['localadmin']){
			$("#admin-status").html("Begrenset administrator");
		}
	}else{
		$("#admin-status").html("Ingen adminrettigheter");
	}
	$("#open-admin-dialog-btn").off();
	$("#open-admin-dialog-btn").on( "click", function() {
  	getAdminProperties(username);
	});
	$("#admin").css('display', 'flex');
	
	//Equipment data
	if(data['devices'].length > 0){
		var devicelist = "";
		$.each(data['devices'], function(i, item) {
			switch(item['type']){
				case "laptop":
					devicelist += "<a href='/index.php?device="+item['id']+"' class='list-group-item list-group-item-action pt-1 pb-1'>";
					devicelist += "<i class='fa fa-fw fa-laptop mr-1'></i>";
					break;
				case "tablet":
					devicelist += "<a href='/index.php?device="+item['id']+"' class='list-group-item list-group-item-action pt-1 pb-1'>";
					devicelist += "<i class='fa fa-fw fa-tablet mr-1'></i>";
					break;
				case "mac":
					devicelist += "<a href='/mac-search.php?device="+item['id']+"' class='list-group-item list-group-item-action pt-1 pb-1'>";
          devicelist += "<i class='fab fa-fw fa-apple mr-1'></i>";
          break;
				case "phone":
					devicelist += "<a href='/mobile-search.php?device="+item['id']+"' class='list-group-item list-group-item-action pt-1 pb-1'>";
          devicelist += "<i class='fa fa-fw fa-mobile mr-1'></i>";
          break;
				case "default":
					devicelist += "<a href='#"+item['id']+"' class='list-group-item list-group-item-action pt-1 pb-1'>";
					devicelist += "<i class='fa fa-fw fa-question'></i>";
			}
    	devicelist += " "+item['device']+" ("+item['description']+")</a>";
  	});
   	$("#devices-container").html(devicelist);
  }else{
    $("#devices-container").html("Ingen enheter registrert på bruker.");
  }
  $("#devices").css('display', 'flex');

	
}

function addNewPhone(){
  $("#phone-output").html("");
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=addNewPhone",
    data: $("#form-new-phone").serialize(),
    success: function(data) {
      $("#phone-output").html("<div class='alert alert-success'>" + data + "</div>");
    },
    error: function(msg) {
      $("#phone-output").html("<div class='alert alert-warning'>"+ msg.responseText + "</div>");
    }
  });

}


function addNewObject(type){
  $("#new-"+ type +"-output").html("");
  if ( (type == "mac-desktop") || (type == "mac-laptop") ) {
    var func = "addEditMacObject";
  }else if(type == "linux-server"){
		var func = "addEditLinuxServer";
	}
  else {
    var func = "addNewObject";
  }
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=" + func,
    data: $("#form-new-" + type).serialize(),
    success: function(data) {
      $("#"+ type +"-output").html("<div class='alert alert-success'>" + data + "</div>");
    },
    error: function(msg) {
      $("#"+ type +"-output").html("<div class='alert alert-warning'>"+ msg.responseText + "</div>");
    }
  });

}

function editObject(){
  var id = $("#mdt-id").val();
  var type = $("#mdt-type").val();
  var data = "&serialnumber=" + $("#misc-serialnumber").val() + "&id=" + id + "&" + $("#form-edit-" + type).serialize();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=editObject",
    data: data,
    success: function(data) {
      $("#computer-properties-dialog").modal("hide");
    },
    error: function(msg) {
      alert("Feil under lagring:\n"+ msg.responseText);
    }
  });
}

function editMacObject(){
  var id = $("#mac-computer-id").val();
  var type = $("#mac-computer-type").val();
  var data = "&id=" + id + "&" + $("#form-edit-mac-" + type).serialize();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=addEditMacObject",
    data: data,
    success: function(data) {
      $("#mac-computer-properties-dialog").modal("hide");
    },
    error: function(msg) {
			alert(msg.responseText);	
    }
  });
}

function editLinuxServer(){
  var data = $("#form-edit-linux").serialize();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=addEditLinuxServer",
    data: data,
    success: function(data) {
      $("#linux-properties-dialog").modal("hide");
    },
    error: function(msg) {
      alert(msg.responseText);
    }
  });
}



function editPhoneObject(){
  var id = $("#phone-id").val();
  var data = "&id=" + id + "&" + $("#form-edit-phone").serialize();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=editPhoneObject",
    data: data,
    success: function(data) {
      $("#phone-properties-dialog").modal("hide");
    },
    error: function(msg) {
      alert(msg.responseText);
    }
  });

}

function showPhoneProperties(phone){
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=getPhoneProperties&phone=" + phone,
    success: function(data) {
      data = JSON.parse(data);
      $("#phone-id").val(data['id']);
			$("#form-edit-phone > input[name=assettag]").val(data['assettag']);
      $("#form-edit-phone > input[name=imei]").val(data['imei']);
      $("#form-edit-phone > input[name=serial]").val(data['serial']);
      $("#form-edit-phone > input[name=owner]").val(data['owner']);
      $("#form-edit-phone > input[name=description]").val(data['description']);
			$("#form-edit-phone > input[name=comment]").val(data['comment']);
			if(data['mdm']['EnrollmentStatus']){
        $("#form-edit-phone > input[name=mdm]").val(data['mdm']['EnrollmentStatus']);
      }else if(data['mdm']['message']){
        $("#form-edit-phone > input[name=mdm]").val(data['mdm']['message']);
      }else{
        $("#form-edit-phone > input[name=mdm]").val(data['mdm']);
      }
			$("#phone-properties-dialog-title").text("Egenskaper for " + data['description'] );
      $("#phone-properties-dialog").modal("show");

    },
    error: function(msg) {
      alert("Klarte ikke å hente informasjon fra serveren.\n\n" + msg.responseText +".");
    }
  });
}

function showLinuxProperties(computer){
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=getLinuxProperties&id=" + computer,
    success: function(data) {
      data = JSON.parse(data);
      $("#linux-id").val(data['id']);
      $("#form-edit-linux > input[name=name]").val(data['name']);
      $("#form-edit-linux > input[name=description]").val(data['description']);
			$("#form-edit-linux > input[name=macaddress]").val(data['macaddress']);
			$("#form-edit-linux input[name=ip4address]").val(data['ip4address']);
      $("#form-edit-linux input[name=ip4gateway]").val(data['ip4gateway']);
			$("#form-edit-linux input[name=ip4subnetmask]").val(data['ip4subnetmask']);
	    $("#form-edit-linux input[name=ip4dns]").val(data['ip4dns']);

			$("#form-edit-linux input[name=ip6address]").val(data['ip6address']);
      $("#form-edit-linux input[name=ip6gateway]").val(data['ip6gateway']);
			$("#form-edit-linux input[name=ip6subnetprefixlength]").val(data['ip6subnetprefixlength']);
      $("#form-edit-linux input[name=ip6dns]").val(data['ip6dns']);
			$("#form-edit-linux select[name=managed]").val(data['managed']);
			$("#linux-role-list").val(data['roles']);	
      $("#form-edit-linux > textarea[name=comment]").val(data['comment']);
      $("#linux-properties-dialog-title").text("Egenskaper for " + data['name'] );
      $("#linux-properties-dialog").modal("show");

    },
    error: function(msg) {
      alert("Klarte ikke å hente informasjon fra serveren.\n\n" + msg.responseText +".");
    }
  });
}


function showMacProperties(computer){

  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=getMacProperties&computer=" + computer,
    success: function(data) {
      data = JSON.parse(data);
      $("#edit-mac-desktop-container,#edit-mac-laptop-container").toggle(false);
      $("#mac-computer-id").val(data['id']);
      $("#mac-computer-type").val(data['type']);
      $("#misc-mac-ip").val(data['ip']);
      $("#misc-mac-user").val(data['user']);
      $("#misc-mac-audit").val(data['reportdate']);
			if(data['mdm']['EnrollmentStatus']){
				$("#misc-mac-mdm").val(data['mdm']['EnrollmentStatus']);
			}else if(data['mdm']['message']){
				$("#misc-mac-mdm").val(data['mdm']['message']);
			}else{
				$("#misc-mac-mdm").val(data['mdm']);
			}
      var description = data['description'].substring(0,data['description'].lastIndexOf("-"));
      var building = description.substring(0,description.indexOf("-"));
      var room = description.substring(description.indexOf("-") + 1);
      switch( data['type']) {
        case "desktop":
          var description = data['description'].substring(0,data['description'].lastIndexOf("-"));
          var building = description.substring(0,description.indexOf("-"));
          var room = description.substring(description.indexOf("-") + 1);
          $("#form-edit-mac-desktop input[name=assettag]").val(data['assettag']);
          $("#form-edit-mac-desktop input[name=serial]").val(data['serial']);
          $("#form-edit-mac-desktop input[name=building]").val(building);
          $("#form-edit-mac-desktop input[name=room]").val(room);
          $("#edit-mac-desktop-container").toggle(true);
          break;
        case "laptop":
          var description = data['description'].substring(0,data['description'].lastIndexOf("-"));
          var building = description.substring(0,description.indexOf("-"));
          var room = description.substring(description.indexOf("-") + 1);
          $("#form-edit-mac-laptop input[name=assettag]").val(data['assettag']);
          $("#form-edit-mac-laptop input[name=serial]").val(data['serial']);
          $("#form-edit-mac-laptop input[name=building]").val(building);
          $("#form-edit-mac-laptop input[name=room]").val(room);
          $("#form-edit-mac-laptop input[name=owner]").val(data['owner']);
          $("#edit-mac-laptop-container").toggle(true);
          break;
      }
      var munkireporturl = "https://report.munki.oslomet.no/index.php?/clients/detail/" + data['serial'];
      $("#misc-mac-munkireport").attr("href", munkireporturl);
      var munkiwebadminurl = "https://webadmin.munki.oslomet.no/manifests/#" + data['name'];
      $("#misc-mac-munkiwebadmin").attr("href", munkiwebadminurl);


      $("#mac-computer-properties-dialog-title").text("Egenskaper for " + data['name'] );
			history.pushState(null, "Maskin" + data['name'], "/mac-search.php/?device=" + data['id']);
      $("#mac-computer-properties-dialog").modal("show");
    },
    error: function(msg) {
      alert("Klarte ikke å hente informasjon fra serveren.\n\n" + msg.responseText +".");

    }
  });
}


function showProperties(computer){
	$("#properties-ad-output").html("");
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=getProperties&computer=" + computer,
    success: function(data) {
      data = JSON.parse(data);
      $("#edit-desktop-container,#edit-laptop-container,#edit-server-container, #edit-virtual-container,#edit-tablet-container").toggle(false);
      $("#mdt-id").val(data['id']);
      $("#mdt-type").val(data['type']);
      $("#sccm-id").val(data['sccm']['id']);
      switch( data['type']) {
        case "desktop":
          var description = data['description'].substring(0,data['description'].lastIndexOf("-"));
          var building = description.substring(0,description.indexOf("-"));
          var room = description.substring(description.indexOf("-") + 1);
          $("#form-edit-desktop input[name=assettag]").val(data['assettag']);
          $("#form-edit-desktop input[name=mac-address]").val(data['mac-address']);
					$("#nav-mac-link-desktop").attr('href',"https://nav.oslomet.no/machinetracker/mac/?days=90&mac="+data['mac-address']);
          $("#form-edit-desktop input[name=building]").val(building);
          $("#form-edit-desktop input[name=room]").val(room);
          $("#form-edit-desktop select[name=role]").val(data['role']);
          $("#edit-desktop-container").toggle(true);
          break;
        case "laptop":
          var description = data['description'].substring(0,data['description'].lastIndexOf("-"));
          var building = description.substring(0,description.indexOf("-"));
          var room = description.substring(description.indexOf("-") + 1);
          $("#form-edit-laptop input[name=assettag]").val(data['assettag']);
          $("#form-edit-laptop input[name=mac-address]").val(data['mac-address']);
					$("#nav-mac-link-laptop").attr('href',"https://nav.oslomet.no/machinetracker/mac/?days=90&mac="+data['mac-address']);
          $("#form-edit-laptop input[name=building]").val(building);
          $("#form-edit-laptop input[name=room]").val(room);
          $("#form-edit-laptop input[name=owner]").val(data['owner']);
          $("#form-edit-laptop select[name=role]").val(data['role']);
          $("#edit-laptop-container").toggle(true);
          break;
        case "virtual":
          $("#form-edit-virtual input[name=assettag]").val(data['assettag']);
          $("#form-edit-virtual input[name=mac-address]").val(data['mac-address']);
          $("#form-edit-virtual input[name=description]").val(data['description']);
          $("#form-edit-virtual select[name=role]").val(data['role']);
          $("#edit-virtual-container").toggle(true);
          break;
        case "server":
          $("#form-edit-server input[name=servername]").val(data['name']);
          $("#form-edit-server input[name=description]").val(data['description']);
          $("#form-edit-server input[name=ip-address]").val(data['server']['ip']);
          $("#form-edit-server input[name=gateway]").val(data['server']['gateway']);
          $("#form-edit-server input[name=netmask]").val(data['server']['netmask']);
          $("#form-edit-server input[name=dns]").val(data['server']['dns']);
          $("#form-edit-server input[name=ipv6-address]").val(data['server']['ipv6-address']);
          $("#form-edit-server input[name=ipv6-gateway]").val(data['server']['ipv6-gateway']);
          $("#form-edit-server input[name=prefix-length]").val(data['server']['prefix-length']);
          $("#form-edit-server input[name=ipv6-dns]").val(data['server']['ipv6-dns']);

          $("#form-edit-server input[name=mac-address]").val(data['mac-address']);
          $("#form-edit-server select[name=mdt-ou]").val(data['server']['ou']);
          $("#form-edit-server select[name=role]").val(data['role']);
          $("#edit-server-container").toggle(true);
          break;
      }
      if (data['exists'] == false){
        $("#form-ad-attributes").toggle(false);
        $("#not-in-ad").toggle(true);
      }
      else{
        $("#not-in-ad").toggle(false);
        $("#form-ad-attributes").toggle(true);
        var ou = data['dn'].substring(data['dn'].indexOf(",") + 1);
        $("#form-ad-attributes > input[name=computername]").val(data['name']);
        $("#form-ad-attributes input[name=adminpassword]").val(data['adminpassword']);
        $("#form-ad-attributes select[name=ou]").val(ou);
        $("#form-ad-attributes select[name=ou]").unbind('change');
        $("#form-ad-attributes select[name=ou]").change(function(){moveADObject();});
        if (data['recoverykey'] > " "){
          $("#recoverykey").html(data['recoverykey']);
          $("#recoverykey-container").show();
        }
        else {
           $("#recoverykey-container").hide();
        }
      }
      if (data['sccm']['model'] == 'Ukjent'){
         $("#misc-model").text(data['sccm']['model']);
      }else{
        $("#misc-model").text(data['sccm']['model'] + " - " + data['sccm']['cpu'] + ", " + data['sccm']['ram']);
      }
      $("#misc-serialnumber").text(data['serial']);
      $("#misc-login").html("<a href='/users.php?user="+data['login']+"'>"+data['login']+"</a> <span class='small'>("+data['timestamp']+")</span>");
      $("#misc-ip").text(data['ip']);
      $("#misc-os-install-date").text(data['sccm']['installdate']);
			$("#misc-os-version").text(data['sccm']['osversion']);
			$("#misc-bios-version").text(data['sccm']['bios']);

      var active = "";
      if (data['active'] == 'NO') {
        active = " - Denne enheten er registert på lager."
      }
			var objectlink = "<a href='https://" + window.location.host + "/?device=" + data['id'] + "'><i class='fa fa-link'></i></a>" ;
			document.title = data['name'] + " - Synopsis";
			history.pushState(null, "Maskin" + data['name'], "/index.php/?device=" + data['id']);
      $("#computer-properties-dialog-title").html("Egenskaper for " + data['name'] + active + " " + objectlink);
      $("#computer-properties-dialog").modal("show");

			getNetworkStatus(data['mac-address'],data['type']);
    },
    error: function(msg) {
      alert("Klarte ikke å hente informasjon fra serveren.\n\n" + msg.responseText +".");
    }
	});
}

function deleteObject(){
  var id = $("#mdt-id").val();
  if ( confirm("Er du sikker på at du vil slette denne enheten?\n\nDersom enheten skal kastes, MÅ du bruke kasseringsfunksjonen.") ){
    $.ajax( {
      type: "POST",
      url: "/functions.php?exec=deleteObject",
      data: "id=" + id,
      success: function(data) {
        $("#computer-properties-dialog").modal("hide");
      },
      error: function(msg) {
        alert("Feil under sletting: \n" + msg.responseText);
      }
    });
  }
}

function restoreDiscardedObject(id){
	var input = prompt("Oppgi begrunnelse for omgjøring av kasseringen.\n\n Ta vare på MAC og tyverinummer slik at du kan registrere den på nytt.");
  if (input){
    $.ajax( {
      type: "POST",
      url: "/functions.php?exec=restoreDiscardedObject",
      data: "id=" + id + "&reason=" + input,
      success: function(data) {
				discardedSearch();
      },
      error: function(msg) {
        alert("Feil under omgjøring av kassering:\n\n" + msg.responseText +".");
      }
    });
  }

}

function approveDiscardedObject(id,type,e){
  var input = confirm("Vil du godkjenne denne kasseringen?");
  if (input){
    $.ajax( {
      type: "POST",
      url: "/functions.php?exec=approveDiscardedObject",
      data: "id=" + id + "&type=" + type,
      success: function(data) {
				$(e).remove();
      },
      error: function(msg) {
        alert("Feil under bekreftelse av kassering:\n\n" + msg.responseText +".");
      }
    });
  }
}


function discardObject(){
  var id = $("#mdt-id").val();
  var input = prompt("Oppgi begrunnelse for kassering");
	if (input){
    $.ajax( {
      type: "POST",
      url: "/functions.php?exec=discardObject",
      data: "id=" + id + "&reason=" + input,
      success: function(data) {
        $("#computer-properties-dialog").modal("hide");
      },
      error: function(msg) {
	      alert("Feil under kassering:\n\n" + msg.responseText +".");
      }
    });
  }
}

function discardPhoneObject(){
  var id = $("#phone-id").val();
	var input = prompt("Oppgi begrunnelse for kassering");
  if ( input){
    $.ajax( {
      type: "POST",
      url: "/functions.php?exec=discardPhoneObject",
      data: "id=" + id + "&reason=" + input,
      success: function(data) {
        $("#phone-properties-dialog").modal("hide");
      },
      error: function(msg) {
				alert("Feil under kassering:\n\n" + msg.responseText +".");
      }
    });
  }
}



function discardMacObject(){
  var id = $("#mac-computer-id").val();
	var input = prompt("Oppgi begrunnelse for kassering");
  if (input){
    $.ajax( {
      type: "POST",
      url: "/functions.php?exec=discardMacObject",
      data: "id=" + id + "&reason=" + input,
      success: function(data) {
        $("#mac-computer-properties-dialog").modal("hide");
      },
      error: function(msg) {
				alert("Feil under kassering:\n\n" + msg.responseText +".");
      }
    });
  }
}

function discardedSearch(){
  $("#discarded-output").html("Søker etter enheter...");
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=getDiscardedObjects",
    data: $("#form-discarded-search").serialize(),
    success: function(data) {
        $("#search-results").html(data);
				$("#search-results > table").DataTable({
          "paging": false,
          "language": {
            url : '/vendor/datatables/norwegian.json'
          }
        });
    },
    error: function(msg) {
      $("#search-results").html("<p>"+ msg.responseText + "</p>");
    }

  });  
}

function moveADObject(){
  $("#properties-ad-output").html("");
  var ou = $("#form-ad-attributes select[name=ou]").val();
  ou = ou.substring(3,ou.indexOf(","));
  if ( confirm("Er du sikker på at du vil flytte dette objektet til OU-en '" + ou + "'?") ){
    $.ajax( {
      type: "POST",
      url: "/functions.php?exec=moveADObject",
      data: $("#form-ad-attributes").serialize(),
      success: function(data) {
        $("#properties-ad-output").html("<div class='alert alert-success mt-2'>"+ data + " Husk at dersom du lagrer vil OU endres til standard for rollen.</div>");
      },
      error: function(msg) {
        $("#properties-ad-output").html("<div class='alert alert-error mt-2'>"+ msg.responseText + "</div>");
      }
    });
  }
}

function setRoleStatus(rolestatus) {
  var rolename = $("#settings-rolelist").val();
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=setRoleProperties&rolename=" + rolename + "&rolestatus=" + rolestatus,
    success: function(data) {
      getRoleProperties(rolename);
    }
  });

}

function getRoleProperties(rolename) {
  $("#rolestatus-admin,#rolestatus-all").hide();
  $('#loading-rolestatus').html("Henter informasjon <i class='fa-spinner fa-spin fa-lg'></i>");

  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=getRoleProperties&rolename=" + rolename,
    success: function(data) {
        if (data == 1){
          $("#rolestatus-all").show();
        }else{
          $("#rolestatus-admin").show();
        }
    }
  });
  $('#loading-rolestatus').html("");
}

function addEditLinuxRole(){
	var	roledata = $("#form-linux-role").serialize();
	$.ajax( {
    type: "POST",
    url: "/functions.php?exec=addEditLinuxRole",
    data: roledata,
    success: function(data) {
			$("#linux-role-dialog").modal("hide");
    },
    error: function(msg){
      alert(msg.responseText);
    }
  });	
}

function addEditRoleSystem(){
  var roledata = $("#form-role-systems").serialize();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=addEditRoleSystem",
    data: roledata,
    success: function(data) {
      $("#role-systems-dialog").modal("hide");
    },
    error: function(msg){
      alert(msg.responseText);
    }
  });
}


function getSystemUser(username){
	$.ajax( {
    type: "GET",
    url: "/functions.php?exec=getSystemUser&username=" + username,
    success: function(data) {
			data = JSON.parse(data);
			$("#username").val(data['username']);
			$("#userlevel").val(data['userlevel']);
			if(data['delegation'] == 1){
				$("#delegation").prop('checked',true);
			}else{
				$("#delegation").prop('checked',false);
			}
			if(data['approval'] == 1){
        $("#approval").prop('checked',true);
      }else{
        $("#approval").prop('checked',false);
      }
			if(data['otpset'] == 1){
				$("#otp-container").html("<button class='btn btn-primary' data-toggle='otp-reset-confirmation' data-title='Bekreft reset' data-content='Nullstill to-faktornøkkel for "+username+"?'><i class='fa fa-undo'></i> Reset to-faktor</button>");
			}else{
				$("#otp-container").html("<button disabled class='btn btn-primary'>To-faktor ikke aktivert</button>");
			}
			$('[data-toggle=otp-reset-confirmation]').confirmation({ rootSelector: '[data-toggle=otp-reset-confirmation]',onConfirm: resetOTP});
			$("#users-dialog").modal("show");
    }
  });

}


function registerWifiUser(){
  var inputdata = $("#form-wifi-user").serialize();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=registerWifiUser",
    data: inputdata,
    success: function(data) {
			data = JSON.parse(data);
			username = data['login'];
			password = data['password'];
			$("#wifiuser-result-text").html("<h5>Bruker opprettet</h5>Brukernavn: "+ username + "<br />Passord: "+ password);
			$("#wifiuser-result").addClass("show");
    },
    error: function(msg){
      alert(msg.responseText);
    }
  });
}


function addEditSystemUser(){
  var userdata = $("#form-users").serialize();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=addEditSystemUser",
    data: userdata,
    success: function(data) {
      $("#users-dialog").modal("hide");
    },
    error: function(msg){
      alert(msg.responseText);
    }
  });
}


function deleteAdminComputer(computer){
	username = $("#admin-username").val();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=deleteAdminComputer",
    data: "username="+ username + "&computer=" + computer,
    success: function(data) {
      $("#admin-no-computers").remove();
      $("#admin-computer-item-" + computer).remove();
    },
    error: function(msg){
      alert(msg.responseText);
    }
  });

}

function addAdminComputer(){
  username = $("#admin-username").val();
	computer = $("#admin-add-computer").val();
	computer = computer.toUpperCase();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=addAdminComputer",
    data: "username="+ username + "&computer=" + computer,
    success: function(data) {
			$("#admin-no-computers").remove();
    	var oldlist = $("#admin-computer-list").html();
			var newlist = '<li id="admin-computer-item-' + computer +'" class="pt-1 pb-1 list-group-item d-flex justify-content-between align-items-center">'+ computer +'<button onclick="deleteAdminComputer(\''+ computer +'\');" class=" p-1 btn btn-primary"><i class="fas fa-times"></i></button></li>';
			$("#admin-computer-list").html(newlist + oldlist);
			$("#admin-add-computer").val("");
    },
    error: function(msg){
      alert(msg.responseText);
    }
  });
}


function setAdminProperties(){
	if($("#admin-type").val() == "none"){
		if(!confirm("Er du sikker på at du vil fjerne alle rettigheter?")){
			return false;
		}
	}
  username = $("#admin-username").val();
  $.ajax( {
    type: "POST",
    url: "/functions.php?exec=setAdminProperties",
    data: $("#form-edit-admin").serialize(),
    success: function(data) {
			getUserData('employee');
      //$("#admin-user-dialog").modal("hide");
    },
    error: function(msg){
      alert(msg.responseText);
    }
  });

}

function getAdminProperties(username){
	$("#admin-add-computer").val("");
  $.ajax( {
    type: "GET",
    url: "/functions.php?exec=getAdminProperties&username=" + username,
    success: function(data) {
      result = JSON.parse(data);
			$("#admin-username").val(username);
			if(result[username] === undefined){
				$("#admin-type, #admin-current").val("none");
				$("#admin-computer-list").html("");	
			}else{
				if(result[username]['classroomadmin'] == true){
					$("#admin-type, #admin-current").val("classroomadmin");
				}else if(result[username]['localadmin']){
					$("#admin-type, #admin-current").val("localadmin");
				}
				var computerlist = "";
				$.each(result[username]['localadmin'], function(i, item) {
			    computerlist += '<li id="admin-computer-item-' + item +'" class="pt-1 pb-1 pr-1 list-group-item d-flex justify-content-between align-items-center">'+ item +
					'<button onclick="deleteAdminComputer(\''+ item +'\');" class="btn btn-primary"> <i class="fas fa-times"></i> </button></li>';
  			});
				$("#admin-computer-list").html(computerlist);
			}
			$("#admin-user-dialog").modal("show");

    },
    error: function(msg){
      alert("Det oppsto en feil under lasting");
    }
  });
}

function getReport(reporttype){
	$("#report-result").html("<i class='fas fa-circle-notch fa-spin fa-lg fa-fw'></i> Laster rapporten...");
	if(!reporttype){
		var reporttype = $("#reporttype").val();
	}
	$.ajax( {
		type: "GET",
	  url: "/report-functions.php",
  	data: "&report=" + reporttype,
	  success: function(data) {
			$("#report-result").html(data);
			$("#report-result > table").DataTable({
          "paging": false,
          "language": {
            url : '/vendor/datatables/norwegian.json'
          }
        });

  	},
	  error: function(msg) {
    alert(msg.responseText);
  	}
	});
}



function resetOTP(){
	var username = $("#username").val();
  $.ajax( {
  	type: "POST",
    url: "/functions.php?exec=resetOTP",
    data: "&username=" + username,
    success: function(data) {
			$("#otp-container").html("<button disabled class='btn btn-primary'>To-faktor ikke aktivert</button>");
    },
    error: function(msg) {
      alert(msg.responseText);
    }
  });
}


function initializeTypeahead(elementId){

	$('#'+elementId).typeahead({
  	highlight: true,
		minLength: 3
	},
	{
  	name: 'label',
  	display: 'value',
  	source: function(query, syncResults, asyncResults) {
    	$.get('/functions.php?exec=usersSearch&term=' + query, function(data) {
				data = $.parseJSON(data);
      	asyncResults(data);
    	});
  	},
		templates: {
        suggestion: function (data) {
            return '<p>' + data.label + '</p>';
        }
    }
	});
}

function getURLParameter(parameter){
	var url_string = window.location.href;
	var url = new URL(url_string);
	return url.searchParams.get(parameter);
}
