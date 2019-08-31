<?php
    require("header.inc.php");
?>

<div class="col-md-10 float-left col px-5 pl-md-4 pt-3 main">
	<div class="page-header">
		<h4><i class="fa fa-search"></i> Søk i Windows-maskiner</h4>
	</div>
	<hr> <!-- End heading -->

	<div class="row">
		<div class="col">
			<form id="form-windows-search" onsubmit="deviceSearch('windows');return false;" class="form-inline">
				<div class="input-group mb-2">
					<div class="input-group-prepend">
						<span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
					</div>
					<input type="text" id="windows-user-search" name="username" class="form-control mr-2" placeholder="Pålogget bruker">
				</div>
				<div class="input-group mb-2">
					<div class="input-group-prepend">
						<span class="input-group-text" id="basic-addon1"><i class="fa fa-fw fa-desktop"></i></span>
					</div>
					<input type="text" name="computername" class="form-control mr-2" placeholder="Maskinnavn">
				</div>
				<div class="input-group mb-2">
					<div class="input-group-prepend">
						<span class="input-group-text" id="basic-addon1"><i class="fa fa-fw fa-building"></i></span>
					</div>
					<input type="text" name="description" class="form-control mr-2" placeholder="Plassering">
				</div>
				<div class="input-group mb-2">
					<div class="input-group-prepend">
						<span class="input-group-text" id="basic-addon1"><i class="fa fa-fw fa-address-card"></i></span>
					</div>
					<input type="text" name="owner" class="form-control mr-2" placeholder="Eier">
				</div>
				<div class="input-group mb-2">
					<div class="input-group-prepend">
						<span class="input-group-text" id="basic-addon1"><i class="fa fa-fw fa-microchip"></i></span>
					</div>
					<input type="text" name="mac-address" class="form-control mr-2" placeholder="MAC-adresse">
				</div>
				<button type="submit" class="btn btn-outline-dark mb-2"><i class="fa fa-fw fa-search"></i> Søk</button>
			</form>
			<hr>
			<div>
			</div>
			<div class="row">
				<div id="search-results" class="col"></div>
			</div>

		</div>

		<!-- Mac dialog -->
		<div class="modal" id="mac-computer-properties-dialog">
			<div class="modal-dialog modal-lg" role="document">
				<div class="modal-content">
					<div class="modal-header">
						<h5 id="mac-computer-properties-dialog-title" class="modal-title">Modal title</h5>
						<button type="button" class="close" data-dismiss="modal" aria-label="Close">
							<span aria-hidden="true">&times;</span>
						</button>
					</div>
					<div class="modal-body">
						<div id="mac-computer-properties-dialog-content" class="container">
							<input type="hidden" id="mac-computer-id" />
							<input type="hidden" id="mac-computer-type" />
							<div id="mac-properties-container">
								<h4>Generelt</h4>
								<div id="edit-mac-desktop-container" style="display:none;">
									<form id="form-edit-mac-desktop" onsubmit="editMacObject('mac-desktop');return false;">
										<input type="hidden" name="type" value="mac-desktop" />
										<label for="assettag" class="wide">Tyverinummer</label>
										<input class="form-control" required name="assettag" type="number" />
										<label for="serial" class="wide">Serienummer</label>
										<input class="form-control" required name="serial" type="text" />
										<div class="row form-group">
											<div class="col">
												<label class="wide">Plassering</label>
												<input class="form-control" autocomplete="off" required list="buildings" placeholder="Bygg" name="building" />
											</div>
											<div class="col">
												<label for="room" class="">Rom</label>
												<input class="form-control" autocomplete="off" required type="text" list="rooms" placeholder="Rom" name="room" />
											</div>
										</div>
										<br /><br />
										<output id="edit-mac-desktop-output"></output>
									</form>
								</div>
								<div id="edit-mac-laptop-container" style="display:none;">
									<form id="form-edit-mac-laptop" onsubmit="editObject('mac-laptop');return false;">
										<input type="hidden" name="type" value="mac-laptop" />
										<label for="assettag" class="wide">Tyverinummer</label>
										<input class="form-control" required name="assettag" type="number" />
										<label for="serial" class="wide">Serienummer</label>
										<input class="form-control" required name="serial" type="text" />
										<div class="row form-group">
											<div class="col">
												<label class="wide">Plassering</label>
												<input class="form-control" autocomplete="off" required list="buildings" placeholder="Bygg" name="building" />
											</div>
											<div class="col">
												<label for="room" class="">Rom</label>
												<input class="form-control" autocomplete="off" required type="text" list="rooms" placeholder="Rom" name="room" />
											</div>
										</div>
										<label class="wide">Eier</label>
										<input class="form-control" required name="owner" type="text" />
										<br /><br />
										<output id="edit-mac-laptop-output"></output>
									</form>
								</div>
							</div>
							<div id="misc-mac-properties-container">
								<h4>Diverse</h4>
								<label class="wide">Siste audit</label>
								<input class="form-control" id="misc-mac-audit" readonly type="text" placeholder="N/A" /><br />
								<label class="wide">Siste IP</label>
								<input class="form-control" id="misc-mac-ip" readonly type="text" placeholder="N/A" /><br />
								<label class="wide">Siste bruker</label>
								<input class="form-control" id="misc-mac-user" readonly type="text" placeholder="N/A" /><br /><br />

								<label><a target="_blank" id="misc-mac-munkiwebadmin" href="#">Åpne i Munki Webadmin <span style="display:inline-block;" class="ui-icon ui-icon-extlink"></span></a></label>
								<label><a target="_blank" id="misc-mac-munkireport" href="#">Åpne i MunkiReport <span style="display:inline-block;" class="ui-icon ui-icon-extlink"></span></a></label>
							</div>
						</div>
					</div>
					<!--End modal content -->
					<div class="modal-footer">
						<div class="mr-auto">
							<button onclick="discardMacObject();" type="button" class="btn btn-danger"><i class="fa fa-trash"></i> Kassér</button>
						</div>
						<button onclick="editMacObject();" type="button" class="btn btn-primary"><i class="fa fa-save"></i> Lagre</button>
						<button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fa fa-close"></i> Lukk</button>
					</div>
				</div>
			</div>
		</div>
		<!-- End Mac dialog -->

		<!-- Start modal -->
		<div class="modal" id="computer-properties-dialog">
			<div class="modal-dialog modal-lg" role="document">
				<div class="modal-content">
					<div class="modal-header">
						<h5 id="computer-properties-dialog-title" class="modal-title">Modal title</h5>
						<button type="button" class="close" data-dismiss="modal" aria-label="Close">
							<span aria-hidden="true">&times;</span>
						</button>
					</div>
					<div class="modal-body">
						<div id="computer-properties-dialog-content" class="container">
							<input type="hidden" id="mdt-id" />
							<input type="hidden" id="mdt-type" />
							<input type="hidden" id="sccm-id" />
							<div id="mdt-properties-container">
								<h5>Microsoft Deployment</h5>
								<div id="edit-desktop-container" style="display:none;">
									<form id="form-edit-desktop" onsubmit="editObject('desktop');return false;">
										<div class="row form-group">
											<div class="col">
												<input type="hidden" name="type" value="desktop" />
												<label for="assettag1" class="wide">Tyverinummer</label>
												<input class="form-control" required name="assettag" id="assettag1" type="tel" <?php if ($_SESSION["synopsis"]['userlevel'] < 9) {
																																	echo "readonly='readonly'";
																																} ?> />
											</div>
											<div class="col">
												<label for="mac-address" class="wide">MAC-adresse</label> <a id="nav-mac-link-desktop" href="https://nav.oslomet.no/machinetracker/mac" target="blank"> Søk i NAV <i class="fas fa-sm fa-external-link-alt"></i></a>
												<div class="input-group">
													<input required class="form-control" name="mac-address" type="text" />
													<div class="input-group-append">
														<span title="Nettverksstatus" class="input-group-text" id="network-status-desktop"><i class="far fa-question-circle fa-fw"></i></span>
													</div>
												</div>
												<!--
								    <label for="mac-address" class="wide">MAC-adresse</label> <a id="nav-mac-link-desktop" href="https://nav.oslomet.no/machinetracker/mac" target="blank"> Søk i NAV <i class="fas fa-sm fa-external-link-alt"></i></a>
						    		<input required class="form-control" name="mac-address" type="text" /> -->
											</div>
										</div>
										<div class="row form-group">
											<div class="col">
												<label class="wide">Plassering</label>
												<input class="form-control" autocomplete="off" required list="buildings" placeholder="Bygg" name="building" />
											</div>
											<div class="col">
												<label for="room" class="">Rom</label>
												<input class="form-control" autocomplete="off" required type="text" list="rooms" placeholder="Rom" name="room" />
											</div>
										</div>
										<div class="row">
											<div class="col">
												<label class="wide">Rolle</label>
												<?php getRoles(); ?>
											</div>
										</div>
										<output id="edit-desktop-output"></output>
									</form>
								</div>
								<div id="edit-laptop-container" style="display:none;" onsubmit="editObject('laptop');return false;">
									<form id="form-edit-laptop">
										<input type="hidden" name="type" value="laptop" />
										<div class="row form-group">
											<div class="col">
												<label for="assettag" class="wide">Tyverinummer</label>
												<input class="form-control" required name="assettag" type="tel" <?php if ($_SESSION["synopsis"]['userlevel'] < 9) {
																													echo "readonly='readonly'";
																												} ?> />
											</div>
											<div class="col">
												<label for="mac-address" class="wide">MAC-adresse</label> <a id="nav-mac-link-laptop" href="https://nav.hioa.no/machinetracker/mac" target="blank"> Søk i NAV <i class="fas fa-sm fa-external-link-alt"></i></a>
												<div class="input-group">
													<input required class="form-control" name="mac-address" type="text" />
													<div class="input-group-append">
														<span title="Nettverksstatus" class="input-group-text" id="network-status-laptop"><i class="far fa-question-circle fa-fw"></i></span>
													</div>
												</div>
											</div>
										</div>
										<div class="row form-group">
											<div class="col">
												<label>Plassering (valgfritt)</label>
												<input class="form-control" autocomplete="off" type="text" list="buildings" placeholder="Bygg" name="building" />
											</div>
											<div class="col">
												<label for="room">Rom</label>
												<input class="form-control" autocomplete="off" type="text" list="rooms" placeholder="Rom" name="room" />
											</div>
										</div>
										<div class="row">
											<div class="col">
												<label for="owner" class="wide">Eier</label>
												<input class="form-control" required name="owner" type="text" placeholder="Brukernavn eller avdelingskode" />
											</div>
											<div class="col">
												<label class="wide">Rolle</label>
												<?php getRoles(); ?>
											</div>
										</div>
										<output id="edit-laptop-output"></output>
									</form>
								</div>
								<div id="edit-virtual-container" style="display:none;">
									<form id="form-edit-virtual" onsubmit="addNewObject('virtual');return false;">
										<div class="form-group row">
											<div class="col">
												<input type="hidden" name="type" value="virtual" />
												<label for="assettag" class="wide">Tyverinummer til verten og løpenr. (f.eks 12345-1)</label>
												<input class="form-control" required name="assettag" type="text" />
											</div>
											<div class="col">
												<label for="mac-address" class="wide">MAC-adresse</label>
												<input class="form-control" required name="mac-address" type="text" />
											</div>
										</div>
										<div class="form-group row">
											<div class="col">
												<label class="wide">Beskrivelse</label>
												<input class="form-control" type="text" name="description" />
											</div>
										</div>
										<div class="row form-group">
											<div class="col">
												<label class="wide">Rolle</label>
												<?php getRoles(); ?>
											</div>
										</div>
										<output id="edit-virtual-output"></output>
									</form>
								</div>
								<div id="edit-server-container" style="display:none;" onsubmit="editObject('server');return false;">
									<form id="form-edit-server">
										<input type="hidden" name="type" value="server" />
										<label for="servername" class="wide">Servernavn</label>
										<input class="form-control" required name="servername" type="text" />
										<label for="mac-address" class="wide">MAC-adresse</label>
										<input class="form-control" required name="mac-address" type="text" />
										<label class="wide">Beskrivelse av serveren</label>
										<input class="form-control" name="description" type="text" />
										&nbsp;
										<div id="ip-accordion">
											<h5>IPv4-detaljer</h5>
											<div>
												<label class="wide">IP-adresse</label>
												<input class="form-control" name="ip-address" type="text" />
												<label class="wide">Gateway</label>
												<input class="form-control" name="gateway" type="text" />
												<label class="wide">Nettmaske</label>
												<input class="form-control" name="netmask" type="text" />
												<label class="wide">DNS-servere</label>
												<input class="form-control" name="dns" type="text" />
											</div>
											<h5>IPv6-detaljer</h5>
											<div>
												<label class="wide">IPv6-adresse</label>
												<input class="form-control" name="ipv6-address" type="text" />
												<label class="wide">Gateway</label>
												<input class="form-control" name="ipv6-gateway" type="text" />
												<label class="wide">Prefikslengde for delnett</label>
												<input class="form-control" name="prefix-length" type="number" />
												<label class="wide">DNS-servere</label>
												<input class="form-control" name="ipv6-dns" type="text" />
											</div>
										</div>
										<label class="wide">OU-plassering</label>
										<?php getOUList("mdt-ou"); ?>
										<div class="row form-group">
											<div class="col">
												<label class="wide">Rolle</label>
												<?php getRoles(); ?>
											</div>
										</div>
										<output id="edit-server-output"></output>
									</form>
								</div>

								<div id="edit-tablet-container" style="display:none;" onsubmit="editObject('tablet');return false;">
									<form id="form-edit-tablet">
										<input type="hidden" name="type" value="tablet" />
										<div class="row">
											<div class="col">
												<label for="assettag" class="wide">Tyverinummer</label>
												<input class="form-control" required name="assettag" type="tel" />
											</div>
											<div class="col">
												<label class="wide">Beskrivelse</label>
												<input class="form-control" name="description" type="text" />
											</div>
										</div>
										<div class="row">
											<div class="col">
												<label for="owner" class="wide">Eier</label>
												<input class="form-control" required name="owner" type="text" placeholder="Brukernavn eller avdelingskode" />
											</div>
										</div>
										<output id="edit-tablet-output"></output>
									</form>
								</div>
							</div>
							<div id="ad-properties-container">
								<h5>Active Directory</h5>
								<div class="alert alert-info" id="not-in-ad">
									Fant ikke dette objektet i Active Directory.
								</div>
								<form id="form-ad-attributes">
									<input type="hidden" name="computername" />
									<div class="row">
										<div class="col-6">
											<label class="wide">OU-plassering</label>
											<?php getOUList(); ?>
										</div>
										<div class="col-4">
											<label for="adminpassword" class="wide">Adminpassord</label>
											<input class="form-control" name="adminpassword" readonly="readonly" type="text" style="font-family: 'Courier New';" />
										</div>
										<div class="col-2">
											<label>&nbsp; </label>
											<button class="btn btn-block btn-outline-primary" type="button" data-toggle="collapse" data-target="#collapseRecoverykey">
												<i class="fa fa-caret-down"></i> BitLocker
											</button>
										</div>
									</div>
									<div id="recoverykey-container">
										<div class="mt-2 collapse" id="collapseRecoverykey">
											<div class="card card-body" id="recoverykey">
											</div>
										</div>
									</div>
								</form>
								<output id="properties-ad-output">
								</output>
							</div>
							<div id="misc-properties-container" style="width: 100%;">
								<h5>Diverse</h5>
								<!--
							<div class="row">
								<div class="col">
								  <i class="fa fa-hdd-o"></i>
								  <output id="misc-model" readonly placeholder="N/A"></output>
								</div>
							</div> -->
								<div class="row">
									<table class="m-2 table table-sm" style="table-layout: fixed;">
										<tbody>
											<tr>
												<th scope="row"><i class="fa fa-hdd"></i> Maskinvare</th>
												<td colspan="3" id="misc-model" style="font-size: small;"></td>
											</tr>
											<tr>
												<th scope="row"><i class="fa fa-user"></i> Siste bruker</th>
												<td id="misc-login">Ukjent</td>
												<th scope="row"><i class="fa fa-download"></i> Sist installert</th>
												<td id="misc-os-install-date">Ukjent</td>
											</tr>
											<tr>
												<th scope="row"><i class="fa fa-code-branch"></i> OS-versjon</th>
												<td id="misc-os-version">Ukjent</td>
												<th scope="row"><i class="fa fa-microchip"></i> BIOS-versjon</th>
												<td id="misc-bios-version">Ukjent</td>
											</tr>
										</tbody>
									</table>
									<!--
                <div class="col">
								  <label class="wide">Serienummer</label>
								  <input class="form-control" id="misc-serialnumber" type="text" readonly placeholder="N/A" />
								</div>
								<div class="col">
								  <label class="wide">Sist installert</label>
								  <input class="form-control" id="misc-os-install-date" readonly type="text" placeholder="N/A" />
								</div>
							</div>
							<div class="form-group row">
								<div class="col">
								  <label class="wide">Siste bruker</label>
								  <input id="misc-login" class="form-control" readonly type="text" placeholder="N/A" />
								</div>
								<div class="col">
									<label for="misc-ip">Siste IP-adresser</label>
								  <input id="misc-ip" class="form-control" readonly type="text" placeholder="N/A" />
								</div> -->
								</div>
							</div>
						</div>
					</div>
					<!--End modal content -->
					<div class="modal-footer">
						<div class="mr-auto">
							<?php
							if ($adminuser) {
								echo '<button class="btn btn-warning" onclick="deleteObject();"><i class="fa fa-ban"></i> Slett fra MDT og AD</button>';
							}
							?>
							<!-- <button type="button" onclick="discardObject();" class="btn btn-danger"><i class="fa fa-trash"></i> Kassér</button> -->
							<button class="btn btn-danger" type="button" data-toggle="confirmation" data-title="Bekreft kassering" data-content="Kassering sletter enheten fra AD og Synopsis">
								<i class="fa fa-trash"></i> Kassér</button>
						</div>
						<button onclick="editObject();" type="button" class="btn btn-primary"><i class="fa fa-save"></i> Lagre</button>
						<button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fa fa-close"></i> Lukk</button>
					</div>
				</div>
			</div>
		</div> <!-- End modal -->

		<?php 
            getLocations("buildings");
		    getLocations("rooms");
        ?>

		<script>
			window.onload = function() {
				initializeTypeahead('windows-user-search');
				$('#windows-user-search').bind('typeahead:select', function(ev, suggestion) {
					$('#form-windows-search').submit();
				});
				$("#windows-user-search").focus();
				var device = getURLParameter("device");
				if (device > "") {
					showProperties(device);
				}
				//confirmation
				$('[data-toggle=confirmation]').confirmation({
					rootSelector: '[data-toggle=confirmation]',
					onConfirm: discardObject
				});
			}
		</script>
		
        <?php 
            require("footer.inc.php");
        ?>