<?php

#Modules and how they can be accessed.

#access:
#user = need to be logged-in to see it
#hidden_on_login = only visible when not logged in

$MODULES = array(
    'log_in' => 'hidden_on_login',
    'change_password' => 'auth',
    'change_ssh_key' => 'auth',
    'log_out' => 'auth'
);

?>
