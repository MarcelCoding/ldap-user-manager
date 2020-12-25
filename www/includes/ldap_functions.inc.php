<?php

$LDAP_IS_SECURE = FALSE;

###################################

function open_ldap_connection()
{

    global $log_prefix, $LDAP, $SENT_HEADERS, $LDAP_DEBUG, $LDAP_IS_SECURE;

    if ($LDAP['ignore_cert_errors'] == TRUE) {
        putenv('LDAPTLS_REQCERT=never');
    }
    $ldap_connection = @ ldap_connect($LDAP['uri']);

    if (!$ldap_connection) {
        print "Problem: Can't connect to the LDAP server at ${LDAP['uri']}";
        die("Can't connect to the LDAP server at ${LDAP['uri']}");
        exit(1);
    }

    ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);
    if ($LDAP_VERBOSE_CONNECTION_LOGS == TRUE) {
        ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
    }

    if (!preg_match("/^ldaps:/", $LDAP['uri'])) {

        $tls_result = @ ldap_start_tls($ldap_connection);

        if ($tls_result != TRUE) {

            error_log("$log_prefix Failed to start STARTTLS connection to ${LDAP['uri']}: " . ldap_error($ldap_connection), 0);

            if ($LDAP["require_starttls"] == TRUE) {
                print "<div style='position: fixed;bottom: 0;width: 100%;' class='alert alert-danger'>Fatal:  Couldn't create a secure connection to ${LDAP['uri']} and LDAP_REQUIRE_STARTTLS is TRUE.</div>";
                exit(0);
            } else {
                if ($SENT_HEADERS == TRUE) {
                    print "<div style='position: fixed;bottom: 0px;width: 100%;height: 20px;border-bottom:solid 20px yellow;'>WARNING: Insecure LDAP connection to ${LDAP['uri']}</div>";
                }
                ldap_close($ldap_connection);
                $ldap_connection = @ ldap_connect($LDAP['uri']);
                ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);
            }
        } else {
            if ($LDAP_DEBUG == TRUE) {
                error_log("$log_prefix Start STARTTLS connection to ${LDAP['uri']}", 0);
            }
            $LDAP_IS_SECURE = TRUE;
        }

    }

    $bind_result = @ ldap_bind($ldap_connection, $LDAP['admin_bind_dn'], $LDAP['admin_bind_pwd']);

    if ($bind_result != TRUE) {

        $this_error = "Failed to bind to ${LDAP['uri']} as ${LDAP['admin_bind_dn']}";
        if ($LDAP_DEBUG == TRUE) {
            $this_error .= " with password ${LDAP['admin_bind_pwd']}";
        }
        $this_error .= ": " . ldap_error($ldap_connection);
        print "Problem: Failed to bind as ${LDAP['admin_bind_dn']}";
        error_log("$log_prefix $this_error", 0);

        exit(1);

    } elseif ($LDAP_DEBUG == TRUE) {
        error_log("$log_prefix Bound to ${LDAP['uri']} as ${LDAP['admin_bind_dn']}", 0);
    }

    return $ldap_connection;

}


###################################

function ldap_auth_username($ldap_connection, $username, $password)
{

    # Search for the DN for the given username.  If found, try binding with the DN and user's password.
    # If the binding succeeds, return the DN.

    global $log_prefix, $LDAP, $LDAP_DEBUG;

    $ldap_search_query = "${LDAP['account_attribute']}=" . ldap_escape($username, "", LDAP_ESCAPE_FILTER);
    $ldap_search = @ ldap_search($ldap_connection, $LDAP['base_dn'], $ldap_search_query);

    if ($LDAP_DEBUG == TRUE) {
        "$log_prefix Running LDAP search: $ldap_search_query";
    }

    if (!$ldap_search) {
        error_log("$log_prefix Couldn't search for ${username}: " . ldap_error($ldap_connection), 0);
        return FALSE;
    }

    $result = ldap_get_entries($ldap_connection, $ldap_search);
    if ($LDAP_DEBUG == TRUE) {
        error_log("$log_prefix LDAP search returned ${result["count"]} records for $username", 0);
    }

    if ($result["count"] == 1) {

        $auth_ldap_connection = open_ldap_connection();
        $can_bind = @ldap_bind($auth_ldap_connection, $result[0]['dn'], $password);
        ldap_close($auth_ldap_connection);

        if ($can_bind) {
            preg_match("/{$LDAP['account_attribute']}=(.*?),/", $result[0]['dn'], $dn_match);
            return $dn_match[1];
            ldap_unbind($auth_ldap_connection);
            if ($LDAP_DEBUG == TRUE) {
                error_log("$log_prefix Able to bind as $username", 0);
            }
        } else {
            if ($LDAP_DEBUG == TRUE) {
                error_log("$log_prefix Unable to bind as ${username}: " . ldap_error($ldap_connection), 0);
            }
            return FALSE;
        }

    }


}

##################################

function ldap_hashed_password($password)
{
    return '{BCRYPT}' . password_hash($password, PASSWORD_BCRYPT);
}

##################################

function ldap_change_password($ldap_connection, $username, $new_password)
{

    global $log_prefix, $LDAP, $LDAP_DEBUG;

    #Find DN of user

    $ldap_search_query = "${LDAP['account_attribute']}=" . ldap_escape($username, "", LDAP_ESCAPE_FILTER);
    $ldap_search = @ ldap_search($ldap_connection, $LDAP['base_dn'], $ldap_search_query);
    if ($ldap_search) {
        $result = @ ldap_get_entries($ldap_connection, $ldap_search);
        if ($result["count"] == 1) {
            $this_dn = $result[0]['dn'];
        } else {
            error_log("$log_prefix Couldn't find the DN for user $username");
            return FALSE;
        }
    } else {
        error_log("$log_prefix Couldn't perform an LDAP search for ${LDAP['account_attribute']}=${username}: " . ldap_error($ldap_connection), 0);
        return FALSE;
    }

    $entries["userPassword"] = ldap_hashed_password($new_password);
    $update = @ ldap_mod_replace($ldap_connection, $this_dn, $entries);

    if ($update) {
        error_log("$log_prefix Updated the password for $username", 0);
        return TRUE;
    } else {
        error_log("$log_prefix Couldn't update the password for ${username}: " . ldap_error($ldap_connection), 0);
        return TRUE;
    }

}

function ldap_get_ssh_key($ldap_connection, $username)
{
    global $log_prefix, $LDAP, $LDAP_DEBUG;

    #Find DN of user

    $ldap_search_query = "${LDAP['account_attribute']}=" . ldap_escape($username, "", LDAP_ESCAPE_FILTER);
    $ldap_search = @ ldap_search($ldap_connection, $LDAP['base_dn'], $ldap_search_query);
    if ($ldap_search) {
        $result = @ ldap_get_entries($ldap_connection, $ldap_search);
        if ($result["count"] == 1) {
            $this_dn = $result[0]['dn'];
        } else {
            error_log("$log_prefix Couldn't find the DN for user $username");
            return FALSE;
        }
    } else {
        error_log("$log_prefix Couldn't perform an LDAP search for ${LDAP['account_attribute']}=${username}: " . ldap_error($ldap_connection), 0);
        return FALSE;
    }

    return ldap_get_entries($ldap_connection, ldap_read($ldap_connection, $this_dn, "(objectclass=*)", array("sshPublicKey")))[0]["sshpublickey"][0];
}

function ldap_change_ssh_key($ldap_connection, $username, $ssh_key)
{

    global $log_prefix, $LDAP, $LDAP_DEBUG;

    #Find DN of user

    $ldap_search_query = "${LDAP['account_attribute']}=" . ldap_escape($username, "", LDAP_ESCAPE_FILTER);
    $ldap_search = @ ldap_search($ldap_connection, $LDAP['base_dn'], $ldap_search_query);
    if ($ldap_search) {
        $result = @ ldap_get_entries($ldap_connection, $ldap_search);
        if ($result["count"] == 1) {
            $this_dn = $result[0]['dn'];
        } else {
            error_log("$log_prefix Couldn't find the DN for user $username");
            return FALSE;
        }
    } else {
        error_log("$log_prefix Couldn't perform an LDAP search for ${LDAP['account_attribute']}=${username}: " . ldap_error($ldap_connection), 0);
        return FALSE;
    }

    $entries["sshPublicKey"] = $ssh_key;
    $update = @ ldap_mod_replace($ldap_connection, $this_dn, $entries);

    if ($update) {
        error_log("$log_prefix Updated the ssh key for $username", 0);
        return TRUE;
    } else {
        error_log("$log_prefix Couldn't update the ssh key for ${username}: " . ldap_error($ldap_connection), 0);
        return TRUE;
    }
}

?>
