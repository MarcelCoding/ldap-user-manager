<?php

set_include_path(".:" . __DIR__ . "/../includes/");

include_once "web_functions.inc.php";
include_once "ldap_functions.inc.php";

set_page_access("user");

if (isset($_POST['change_ssh_key'])) {
    $ldap_connection = open_ldap_connection();
    ldap_change_ssh_key($ldap_connection, $USER_ID, $_POST['ssh_key']) or die("change_ssh_key_failed() failed.");

    render_header("SSH Key changed");
    ?>
    <div class="alert alert-success">
        <p class="text-center">Your SSH Key has been changed.</p>
    </div>
    <?php
    render_footer();
    exit(0);
}

render_header('Change your LDAP SSH Key');
?>

<div class="container">
    <div class="col-sm-8">

        <div class="panel panel-default">
            <div class="panel-heading text-center">Change SSH Key</div>
            <div class="panel-body text-center">

                <form class="form-horizontal" action='' method='post'>

                    <input type='hidden' id="change_ssh_key" name="change_ssh_key">

                    <div class="form-group" id="ssh_key_div">
                        <label for="ssh_key" class="col-sm-4 control-label">SSH Key</label>
                        <div class="col-sm-6">
                            <textarea class="form-control" id="ssh_key" name="ssh_key"></textarea>
                        </div>
                    </div>

                    <div class="form-group">
                        <button type="submit" class="btn btn-default">Change SSH Key</button>
                    </div>

                </form>
            </div>
        </div>

    </div>
</div>
<?php

render_footer();

?>

