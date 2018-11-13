<?php
/**
 * @author Tim Boormans
 * @copyright Direct Web Solutions B.V.
 * @since October 2018
 */

// include OpenVPN/PFSense intelligence (READ THE DOCS!)
require_once("certs.inc");
require_once("auth.inc");
require_once("pfsense-utils.inc");
require_once("openvpn.inc");
require_once("pkg-utils.inc");
require_once("globals.inc");
require_once("openvpn-client-export.inc");

// openvpn automation globals
$a_user = &$config['system']['user'];
$a_cert = &$config['cert'];
$id = 0; // array element id of the account that we want to modify
$ovpna_error = array();


/**
 * Automation class for automatic provisioning of accounts on your OpenVPN Community Edition server.
 *
 * Class OpenVPN_Automation
 */
class OpenVPN_Automation {

    /**
     * Check the selected user to edit. If not present, the script cannot continue.
     */
    public static function load_user_id() {

        global $a_user, $REQ, $id;

        foreach($a_user as $elem_id => $array) {
            if($array['name'] == $REQ['username']) {
                $id = $elem_id; // search openvpn userID
            }
        }

        if($id == 0) {
            return false;
        } else {
            return true;
        }

    }

    /**
     * Make sure only 'users' can be modified using these functions.
     * Admin accounts and admin roles should not be editable via this API.
     */
    public static function security_check_user_id() {

        global $config, $id;

        // security check: admins may not be edited
        $admin_linux_uids = array();
        foreach($config['system']['group'] as $group) {
            if($group['name'] == 'admins') {
                $admin_linux_uids = $group['member'];
            }
        }

        $admin_user_elem_ids = array(0); // 0 == pfsense admin, but not in the admins group!
        foreach($config['system']['user'] as $user_elem_id => $user) {
            if(in_array($user['uid'], $admin_linux_uids)) {
                $admin_user_elem_ids[] = $user_elem_id;
            }
        }

        if(in_array($id, $admin_user_elem_ids)) {
            return false;
        } else {
            return true;
        }

    }

    /**
     * Add a user to the *nix system and to the OpenVPN configuration inside PFSense
     * @param $username
     * @param $password1
     * @param $password2
     * @return bool
     */
    public static function user_add($username, $password1, $password2) {

        global $config, $a_user;

        $REQ = array();
        $REQ['scope'] = 'user';
        $REQ['descr'] = '';
        $REQ['authorizedkeys'] = '';
        $REQ['ipsecpsk'] = '';
        $REQ['usernamefld'] = $username;
        $REQ['passwordfld1'] = $password1;
        $REQ['passwordfld2'] = $password2;
        $REQ['name'] = trim($username); // 'Descriptive name' is the same as the username
        $REQ['caref'] = ''; // 5a008a51600dc

        // generate password hash by reference (into $REQ )
        local_user_set_password($REQ, $REQ['passwordfld1']);

        // get certificate reference
        foreach($config['openvpn']['openvpn-server'] as $cert_conf) {
            if(strtoupper($cert_conf['description']) == OpenVPN_Automation_Server_Config::$cert_description_uppercase) { // upper cmp
                $REQ['caref'] = $cert_conf['caref'];
            }
        }

        $ca = lookup_ca($REQ['caref']);
        if (!$ca) {
            $input_errors[] = "Invalid internal Certificate Authority";
        }

        $REQ['keylen'] = 2048;
        $REQ['lifetime'] = 3650;

        foreach($config['ovpnserver'] as $step_arr) {
            foreach($step_arr as $keyname => $value) {
                if($keyname == 'certca' && strtoupper($value) == OpenVPN_Automation_Server_Config::$cert_ca_uppercase) { // upper cmp
                    if(intval($step_arr['lifetime']) != 0) {
                        $REQ['lifetime'] = intval($step_arr['lifetime']); // 3650
                    }
                }
            }
        }

        /**
         * Validate base request
         */
        self::validate_new_credentials($REQ);


        /**
         * Configure extra parameters
         */
        $REQ['utype'] = 'user';
        $REQ['expires'] = '';

        /**
         * Pfsense copied + adjusted code:
         */
        $userent = array();
        $userent['cert'] = array();

        $cert = array();
        $cert['refid'] = uniqid();
        $cert['descr'] = $REQ['usernamefld'];

        $subject = cert_get_subject_array($ca['crt']);

        $dn = array(
            'countryName' => $subject[0]['v'],
            'stateOrProvinceName' => $subject[1]['v'],
            'localityName' => $subject[2]['v'],
            'organizationName' => $subject[3]['v'],
            'emailAddress' => $subject[4]['v'],
            'commonName' => $REQ['usernamefld']
        );

        $altnames_tmp = array(cert_add_altname_type($REQ['usernamefld']));
        if (!empty($altnames_tmp)) {
            $dn['subjectAltName'] = implode(",", $altnames_tmp); // string(14) "DNS:test-user4"
        }

        cert_create($cert, $REQ['caref'], $REQ['keylen'], (int)$REQ['lifetime'], $dn);

        if (!is_array($config['cert'])) {
            $config['cert'] = array();
        }

        $config['cert'][] = $cert;
        $userent['cert'][] = $cert['refid'];

        $userent['uid'] = $config['system']['nextuid']++;

        /* Add the user to 'All Users' group. */
        foreach ($config['system']['group'] as $gidx => $group) {

            if ($group['name'] == "all") {

                if (!is_array($config['system']['group'][$gidx]['member'])) {
                    $config['system']['group'][$gidx]['member'] = array();
                }

                $config['system']['group'][$gidx]['member'][] = $userent['uid'];

                break;
            }

        }

        // copy all missing keys to request variable
        foreach($REQ as $k => $v) {
            if(!array_key_exists($k, $userent)) {
                $userent[$k] = $v;
            }
        }

        // create the *nix system user and related configurations
        local_user_set($userent);

        // create the openvpn user
        $a_user[] = $userent;

        // update all configs and references
        self::run_afterwards($userent);

        return true;
    }

    /**
     * Function not implemented yet.
     * @param $username
     */
    public static function user_modify($username) {

        // TODO: UNTESTED CODE:
        /*
        global $a_user, $id;

        if(!self::load_user_id()) {
            $ovpna_error = array('code' => -2, 'msg' => 'OpenVPN-user not found.');
            return false;
        }
        if(!self::security_check_user_id()) {
            $ovpna_error = array('code' => -4, 'msg' => 'Security error. You are trying to edit an Admin. That is not allowed. Exiting.');
            return false;
        }

        $userent = array();
        if (isset($id) && $a_user[$id]) {
            $userent = $a_user[$id];
        }

        $_SERVER['REMOTE_USER'] = $REQ['usernamefld'];
        local_user_del($userent);

        $userent['name'] = $REQ['usernamefld'];
        $userent['expires'] = $REQ['expires'];
        $userent['dashboardcolumns'] = 2;
        $userent['authorizedkeys'] = '';
        $userent['ipsecpsk'] = $REQ['ipsecpsk'];

        $a_user[$id] = $userent;

        // update all configs and references
        self::run_afterwards($userent);

        return true;
        */

    }


    /**
     * Change the password of a OpenVPN user
     * @param $username
     * @param $password
     * @return bool
     */
    public static function user_change_password($username, $password) {

        global $a_user, $id, $ovpna_error;

        if(!self::load_user_id()) {
            $ovpna_error = array('code' => -2, 'msg' => 'OpenVPN-user not found.');
            return false;
        }
        if(!self::security_check_user_id()) {
            $ovpna_error = array('code' => -4, 'msg' => 'Security error. You are trying to edit an Admin. That is not allowed. Exiting.');
            return false;
        }

        $id = 0;
        foreach($a_user as $elem_id => $array) {
            if($array['name'] == $username) {
                $id = $elem_id;
                $userent = $array;
            }
        }

/*
        // also works:
        $userent = array();
        if (isset($id) && $a_user[$id]) {
            $userent = $a_user[$id];
        }
*/

        // generate password hash by reference (into $REQ )
        local_user_set_password($userent, $password);

        /*
        $userent['name'] = $username;
        $userent['expires'] = '';
        $userent['dashboardcolumns'] = 2;
        $userent['authorizedkeys'] = '';
        */

        $a_user[$id] = $userent;

        self::run_afterwards($userent);

        return true;
    }

    /**
     * Delete an OpenVPN user and the *nix system user
     * @param $username
     * @return bool
     */
    public static function user_delete($username) {

        global $a_user, $a_cert, $id, $ovpna_error;

        if(!self::load_user_id()) {
            $ovpna_error = array('code' => -2, 'msg' => 'OpenVPN-user not found.');
            return false;
        }
        if(!self::security_check_user_id()) {
            $ovpna_error = array('code' => -4, 'msg' => 'Security error. You are trying to edit an Admin. That is not allowed. Exiting.');
            return false;
        }

/*        $userent = array();
        if (isset($id) && $a_user[$id]) {
            $userent = $a_user[$id];
        }*/

        // 1: delete user certificate
        foreach($a_user as $elem_id => $array) {
            if($array['name'] == $username) {
                unset($a_user[$elem_id]['cert']); // remove user reference to all certificates
            }
        }
        foreach($a_cert as $elem_id => $array) {
            if($array['descr'] == $username) {
                unset($a_cert[$elem_id]); // remove user certificates from local store
            }
        }

        // 2: delete *nix system user
        local_user_del($a_user[$id]);
        unset($a_user[$id]);

        // 3: delete openvpn config item
        $a_user = array_values($a_user); /* Reindex the array to avoid operating on an incorrect index https://redmine.pfsense.org/issues/7733 */
        write_config();

        // update all configs and references
        //self::run_afterwards($userent); // Do not enable, it will brake the user deletion for some reason!

        return true;
    }


    /**
     * Create a routing profile for the OpenVPN User
     * @param $username
     * @param $ipv4
     * @param $ipv6
     * @return bool
     */
    public static function user_add_ip_routing($username, $ipv4, $ipv6) {

        global $openvpn_tls_server_modes, $config, $a_user, $id, $ovpna_error;

        if(!self::load_user_id()) {
            $ovpna_error = array('code' => -2, 'msg' => 'OpenVPN-user not found.');
            return false;
        }
        if(!self::security_check_user_id()) {
            $ovpna_error = array('code' => -4, 'msg' => 'Security error. You are trying to edit an Admin. That is not allowed. Exiting.');
            return false;
        }

        $a_csc = &$config['openvpn']['openvpn-csc'];

        // calculate subnet
        $ex = explode('.', $ipv4);
        $last_octet_ipv4 = $ex[3];


        // autoconfig
        $pconfig['common_name'] = $username;
        $pconfig['custom_options'] = 'ifconfig-push '.$ipv4.' 255.255.255.0;ifconfig-ipv6-push '.$ipv6.'/124;auth-nocache;';
        $pconfig['act'] = 'new';
        $pconfig['save'] = 'Save';


        // process to VPN settings database
        $csc = array();

        if (is_array($pconfig['server_list'])) {
            $csc['server_list'] = implode(",", $pconfig['server_list']);
        } else {
            $csc['server_list'] = "";
        }

        $csc['custom_options'] = $pconfig['custom_options'];
        $csc['common_name'] = $pconfig['common_name'];

        $csc['block'] = $pconfig['block'];
        $csc['description'] = $pconfig['description'];
        $csc['tunnel_network'] = $pconfig['tunnel_network'];
        $csc['tunnel_networkv6'] = $pconfig['tunnel_networkv6'];
        $csc['local_network'] = $pconfig['local_network'];
        $csc['local_networkv6'] = $pconfig['local_networkv6'];
        $csc['remote_network'] = $pconfig['remote_network'];
        $csc['remote_networkv6'] = $pconfig['remote_networkv6'];
        $csc['gwredir'] = $pconfig['gwredir'];
        $csc['push_reset'] = $pconfig['push_reset'];

        if ($pconfig['dns_domain_enable']) {
            $csc['dns_domain'] = $pconfig['dns_domain'];
        }

        if ($pconfig['dns_server_enable']) {
            $csc['dns_server1'] = $pconfig['dns_server1'];
            $csc['dns_server2'] = $pconfig['dns_server2'];
            $csc['dns_server3'] = $pconfig['dns_server3'];
            $csc['dns_server4'] = $pconfig['dns_server4'];
        }

        if ($pconfig['ntp_server_enable']) {
            $csc['ntp_server1'] = $pconfig['ntp_server1'];
            $csc['ntp_server2'] = $pconfig['ntp_server2'];
        }

        $csc['netbios_enable'] = $pconfig['netbios_enable'];
        $csc['netbios_ntype'] = $pconfig['netbios_ntype'];
        $csc['netbios_scope'] = $pconfig['netbios_scope'];

        if ($pconfig['netbios_enable']) {
            if ($pconfig['wins_server_enable']) {
                $csc['wins_server1'] = $pconfig['wins_server1'];
                $csc['wins_server2'] = $pconfig['wins_server2'];
            }

            if ($pconfig['dns_server_enable']) {
                $csc['nbdd_server1'] = $pconfig['nbdd_server1'];
            }
        }

        $a_csc[] = $csc;
        $wc_msg = sprintf(gettext('Added OpenVPN client specific override %1$s %2$s'), $csc['common_name'], $csc['description']);

        if (!empty($old_csc['common_name'])) {
            openvpn_delete_csc($old_csc);
        }

        openvpn_resync_csc($csc);
        write_config($wc_msg);

        return true;
    }


    /**
     * Remove the routing profile for a specific OpenVPN user.
     * @param $username
     * @return bool
     */
    public static function user_clear_ip_routing($username) {

        global $config, $a_user, $id, $ovpna_error;


        if(!self::load_user_id()) {
            $ovpna_error = array('code' => -2, 'msg' => 'OpenVPN-user not found.');
            return false;
        }
        if(!self::security_check_user_id()) {
            $ovpna_error = array('code' => -4, 'msg' => 'Security error. You are trying to edit an Admin. That is not allowed. Exiting.');
            return false;
        }

        $old_csc['common_name'] = $username;
        openvpn_delete_csc($old_csc);

        // find overrides for this username
        $del_elems = array();
        foreach($config['openvpn']['openvpn-csc'] as $elem_id => $csc_array) {
            if($csc_array['common_name'] == $username) {
                $del_elems[] = $elem_id;
            }
        }

        // delete the override arrays
        foreach($del_elems as $elem_id) {
            unset($config['openvpn']['openvpn-csc'][$elem_id]);
        }

        openvpn_resync_csc($csc); // TODO: check $csc
        write_config('Removed routes for user: '.$username);

        return true;
    }

    /**
     * Run this function to make sure the configs get updated correctly.
     * @param $userent
     * @return bool
     */
    public static function run_afterwards($userent) {

        local_user_set_groups($userent); /* Add user to groups so PHP can see the memberships properly or else the user's shell account does not get proper permissions (if applicable) See #5152. */
        local_user_set($userent);
        local_user_set_groups($userent); /* Add user to groups again to ensure they are set everywhere, otherwise the user may not appear to be a member of the group. See commit:5372d26d9d25d751d16865ed9d46869d3b0ec5e1. */
        write_config();

        if (is_dir("/etc/inc/privhooks")) {
            run_plugins("/etc/inc/privhooks");
        }

        return true;
    }


    /**
     * Internal subfunction to validate input
     * @param $REQ
     * @param string $current_username
     * @return bool
     */
    public static function validate_new_credentials($REQ, $current_username = '') {

        $new_username = $REQ['usernamefld'];
        $password1 = $REQ['passwordfld1'];
        $password2 = $REQ['passwordfld2'];
        $ipsecpsk = $REQ['ipsecpsk'];

        global $config, $ovpna_error;

        $input_errors = array();

        if (preg_match("/[^a-zA-Z0-9\.\-_]/", $new_username)) {
            $input_errors[] = "The username contains invalid characters.";
        }

        if ($new_username == '') {
            $input_errors[] = "The username is required.";
        }

        if (strlen($new_username) > 16) {
            $input_errors[] = "The username is longer than 16 characters.";
        }

        if (($password1) && ($password1 != $password2)) {
            $input_errors[] = "The passwords do not match.";
        }

        if (isset($ipsecpsk) && $ipsecpsk != '' && !preg_match('/^[[:ascii:]]*$/', $ipsecpsk)) {
            $input_errors[] = "IPsec Pre-Shared Key contains invalid characters.";
        }

        if($current_username != '') {
            // make sure this user name is unique
            foreach ($config['system']['user'] as $userent) {
                if ($userent['name'] == $new_username && $current_username != $new_username) {
                    $input_errors[] = "Another entry with the same username already exists.";
                    break;
                }
            }
        }

        if($current_username != '') {
            // make sure it is not reserved
            $system_users = explode("\n", file_get_contents("/etc/passwd"));
            foreach ($system_users as $s_user) {
                $ent = explode(":", $s_user);
                if ($ent[0] == $new_username && $current_username != $new_username) {
                    $input_errors[] = "That username is reserved by the system.";
                    break;
                }
            }
        }

        if(count($input_errors) > 0) {
            $ovpna_error = array('code' => -2, 'msg' => 'Input errors: '.print_r($input_errors, true));
            return false;
        } else {
            return true;
        }

    }

    public static function clean_username($input_username) {
        if(!preg_match('/^([a-z0-9]{1,25}-[a-z0-9]{1,25})$/', $input_username)) { // TODO: Our project requires a dash in the username!
            return '';
        } else {
            return $input_username;
        }
    }

    public static function clean_password($input_password) {
        if(!preg_match('/^([a-zA-Z0-9-_!@#$%^&*()]{6,50})$/', $input_password)) { // TODO: Our project requires 100% input validation to prevent SQL injection. You may expand the allowed characters.
            return '';
        } else {
            return $input_password;
        }
    }

    public static function clean_ipv4($input_ipv4) {
        if(!filter_var($input_ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !filter_var($input_ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) || !filter_var($input_ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)) {
            return '';
        } else {
            return $input_ipv4;
        }
    }

    public static function clean_ipv6($input_ipv6) {
        if(!filter_var($input_ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) || !filter_var($input_ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) || !filter_var($input_ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)) {
            return '';
        } else {
            return $input_ipv6;
        }
    }

    public static function clean_device_operating_systems($input_device_os) {
        // available operating systems
        $deviceOSes = array(
            'windows',
            'linux',
            'macos',
            'iphone',
            'android'
        );

        if(!in_array($input_device_os, $deviceOSes)) {
            return '';
        } else {
            return $input_device_os;
        }
    }

    public static function package_setup_file($user_elem_id, $deviceOS) {

        global $current_openvpn_version, $current_openvpn_version_rev, $legacy_openvpn_version, $legacy_openvpn_version_rev;

        $act = 'confinline';
        $srvid = 2;
        $usrid = $user_elem_id;
        $crtid = 0;
        $srvcfg = get_openvpnserver_by_id($srvid);

        $cfg = &$config['installedpackages']['vpn_openvpn_export']['defaultsettings'];
        $useaddr = $cfg['useaddr_hostname'];

        $verifyservercn = 'auto';
        $blockoutsidedns = 0;
        $legacy = 0;
        $randomlocalport = 0;
        $usetoken = 0;

        if ($srvcfg['mode'] == "server_user") {
            $nokeys = true;
        } else {
            $nokeys = false;
        }

        $proxy = '';
        $expformat = '';
        $desires_filename = "openvpn-".openvpn_client_export_prefix($srvid, $usrid, $crtid)."-install-";
        $password = '';
        $advancedoptions = '';
        $usepkcs11 = 0;
        $pkcs11providers = '';
        $pkcs11id = '';

        $setup_version = '';
        $exp_path = '';

        // TODO: This is specific to our project, but you can modify it to your own needs
        if($deviceOS == 'windows') {

            $desires_filename .= urlencode("{$current_openvpn_version}-I6{$current_openvpn_version_rev}.exe");
            $setup_version = '24'; // 2.4

        } elseif($deviceOS == 'linux') {
            // none, use the linux package manager

        } elseif($deviceOS == 'macos') {
            // none, see mac store

        } elseif($deviceOS == 'iphone') {
            // none, see Itunes App Store

        } elseif($deviceOS == 'android') {
            // none, see Google Play store
        }
        // TODO ends here

        if($desires_filename != '') {

            $exp_path = openvpn_client_export_installer($srvid, $usrid, $crtid, $useaddr, $verifyservercn, $blockoutsidedns, $legacy, $randomlocalport, $usetoken, $password, $proxy, $advancedoptions, $setup_version, $usepkcs11, $pkcs11providers, $pkcs11id);

            rename($exp_path, '/tmp/'.$desires_filename);

            return $desires_filename;

        } else {
            return '';
        }

    }

    public static function package_config_file($user_elem_id, $deviceOS) {

        $act = 'confinline';
        $srvid = 2;
        $usrid = $user_elem_id;
        $crtid = 0;
        $srvcfg = get_openvpnserver_by_id($srvid);

        $cfg = &$config['installedpackages']['vpn_openvpn_export']['defaultsettings'];
        $useaddr = $cfg['useaddr_hostname'];

        $verifyservercn = 'auto';
        $blockoutsidedns = 0;
        $legacy = 0;
        $randomlocalport = 0;
        $usetoken = 0;

        if ($srvcfg['mode'] == "server_user") {
            $nokeys = true;
        } else {
            $nokeys = false;
        }

        $proxy = '';
        $expformat = '';
        $exp_name = openvpn_client_export_prefix($srvid, $usrid, $crtid);
        $password = '';
        $advancedoptions = '';
        $usepkcs11 = 0;
        $pkcs11providers = '';
        $pkcs11id = '';

        // TODO: This is specific to our project, but you can modify it to your own needs
        if($deviceOS == 'windows') {
            // none. Windows uses the all-in installer which just adds the configuration file to the existing installation if present.
            // also the setup files can be unzipped to extract all separate files.

        } elseif($deviceOS == 'linux') {

            $exp_name = urlencode($exp_name . "-linux-config.ovpn");
            $expformat = "inline"; // inline regular

        } elseif($deviceOS == 'macos') {

            $exp_name = urlencode($exp_name . "-macos-config.ovpn");
            $expformat = "inlinevisc"; // inline viscosity

        } elseif($deviceOS == 'iphone') {

            $exp_name = urlencode($exp_name . "-iphone-config.ovpn");
            $expformat = "inlinevisc"; // inline viscosity

        } elseif($deviceOS == 'android') {

            $exp_name = urlencode($exp_name . "-android-config.ovpn");
            $expformat = "inline"; // inline regular

        }
        // TODO ends here

        if($expformat != '') {

            $config_file_contents = openvpn_client_export_config($srvid, $usrid, $crtid, $useaddr, $verifyservercn, $blockoutsidedns, $legacy, $randomlocalport, $usetoken, $nokeys, $proxy, $expformat, $password, false, false, $advancedoptions, $usepkcs11, $pkcs11providers, $pkcs11id);

            if($deviceOS == 'linux') {
                $config_file_contents = str_replace('ncp-disable', '#ncp-disable', $config_file_contents);
            }

            $wr = fopen('/tmp/'.$exp_name, "w");
            if($wr) {
                fwrite($wr, $config_file_contents);
                fclose($wr);
            }

            return $exp_name;

        } else {

            return '';
        }

    }

    public static function find_user_id_by_username($username) {

        global $a_user;

        foreach($a_user as $elem_id => $array) {
            if($array['name'] == $username) {
                return $elem_id; // search openvpn userID
            }
        }

        return '';

    }

    public static function send_file_to_browser($filename) {

        // output headers
        header('Pragma: ');
        header('Cache-Control: ');
        header("Content-Type: application/octet-stream");
        header("Content-Disposition: attachment; filename=".$filename);

        // output data
        print $filename;

    }

    public static function generate_new_password() {
        $nc = 12;
        $chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $l=strlen($chars)-1; $r='';
        while($nc-->0) $r.=$chars{mt_rand(0,$l)};
        return $r;
    }

}