<?php
// intelligence
require('../src/config/OpenVPN_Automation.config.php');
require('../src/class/OpenVPN_Automation.class.php');

// init
/* @var $ovpna_reponse array */
$new_password = OpenVPN_Automation::generate_new_password();


// Control
if(!OpenVPN_Automation::user_add('someuser-dashedname', $new_password, $new_password)) {
    print_r($ovpna_reponse);
    exit();
}

if(!OpenVPN_Automation::user_clear_ip_routing('someuser-dashedname')) {
    print_r($ovpna_reponse);
    exit();
}

if(!OpenVPN_Automation::user_add_ip_routing('someuser-dashedname', '1.2.3.4', '1:2:3:4:5:6:7:8')) {
    print_r($ovpna_reponse);
    exit();
}

if(!OpenVPN_Automation::user_delete('someuser-dashedname')) {
    print_r($ovpna_reponse);
    exit();
}

if(!OpenVPN_Automation::user_change_password('someuser-dashedname', $new_password)) {
    print_r($ovpna_reponse);
    exit();
}

//if(!OpenVPN_Automation::user_modify(/* not yet implemented */)) {
//    print_r($ovpna_reponse);
//    exit();
//}

$user_id = OpenVPN_Automation::find_user_id_by_username('someuser-dashedname');
if($user_id != 0) {

    // generate custom setup file
    $setup_filename = OpenVPN_Automation::package_setup_file($user_id, 'windows');
    OpenVPN_Automation::send_file_to_browser('/tmp/'.$setup_filename);
    unlink('/tmp/'.$setup_filename);

    // generate custom config
    $config_filename = OpenVPN_Automation::package_config_file($user_id, 'linux');
    OpenVPN_Automation::send_file_to_browser('/tmp/'.$config_filename);
    unlink('/tmp/'.$config_filename);
}