<?php
/*
Plugin Name: Crowd Login
Plugin URI:
Description:  Authenticates Wordpress usernames against Atlassian Crowd.
Version: 0.1
Author: Andrew Teixeira
Author URI:
*/

require_once( WP_PLUGIN_DIR."/crowd-login/httpful.phar");
require_once( ABSPATH . WPINC . '/registration.php');

//Admin
function crowd_menu() {
	include 'Crowd-Login-Admin.php';
}

function crowd_admin_actions() {
	add_options_page("Crowd Login", "Crowd Login", 10, "crowd-login", "crowd_menu");
}

function crowd_activation_hook() {
	//Store settings
	add_option('crowd_url', 'https://crowd.mydomain.local:8443/crowd');
	add_option('crowd_app_name', 'crowdlogin');
	add_option('crowd_app_password', 'crowdpassword');
	add_option('crowd_domain_controllers', 'crowd01.mydomain.local');
	add_option('crowd_security_mode', 'security_low');
	add_option('crowd_login_mode', 'mode_normal');
	add_option('crowd_account_type', 'Contributor');
}

// Reset Crowd instance and principal token
$crowd = NULL;
$princ_token = NULL;

//Add the menu
add_action('admin_menu', 'crowd_admin_actions');

//Add filter
add_filter('authenticate', 'crowd_authenticate', 1, 3);

//Authenticate function
function crowd_authenticate($user, $username, $password) {
	if ( is_a($user, 'WP_User') ) { return $user; }

	//Failed, should we let it continue to lower priority authenticate methods?
	if(get_option('crowd_security_mode') == 'security_high') {
		remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);
	}

	if ( empty($username) || empty($password) ) {
		$error = new WP_Error();

		if ( empty($username) ) {
			$error->add('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
		}

		if ( empty($password) ) {
			$error->add('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));
		}
		return $error;
	}

	$auth_result = crowd_can_authenticate($username, $password);
	if($auth_result == true) {
		$user = get_userdatabylogin($username);

		if ( !$user || (strtolower($user->user_login) != strtolower($username)) ) {
			//No user, can we create?
			switch(get_option('crowd_login_mode')) {
				case 'mode_create_all':
					$new_user_id = crowd_create_wp_user($username);
					if(!is_a($new_user_id, 'WP_Error')) {
						//It worked
						return new WP_User($new_user_id);
					} else {
						do_action( 'wp_login_failed', $username );
						return new WP_Error('invalid_username', __('<strong>Crowd Login Error</strong>: Crowd credentials are correct and user creation is allowed but an error occurred creating the user in Wordpress. Actual WordPress error: '.$new_user_id->get_error_message()));
					}
					break;

				default:
					do_action( 'wp_login_failed', $username );
					return new WP_Error('invalid_username', __('<strong>Crowd Login Error</strong>: Crowd Login mode does not permit account creation.'));
			}
		} else {
				return new WP_User($user->ID);
		}
	} else {
		if(is_a($auth_result, 'WP_Error')) {
			return $auth_result;
		} else {
			return new WP_Error('invalid_username', __('<strong>Crowd Login Error</strong>: Crowd Login could not authenticate your credentials. The security settings do not permit trying the Wordpress user database as a fallback.'));
		}
	}
}

function crowd_can_authenticate($username, $password) {

  $response = \Httpful\Request::post(get_option('crowd_url') . '/rest/usermanagement/1/authentication?username='.$username)
			->withXAtlassianToken('no-check')
      ->sendsJson()
			->addHeader('User-Agent', 'Wordpress')
			->authenticateWith(get_option('crowd_app_name'), get_option('crowd_app_password'))
			->body(json_encode(array('value' => $password)))
      ->send();
	return ($response->code == 200);
}

function crowd_create_wp_user($username) {

	$result = 0;
	$person = getUserInfo($username);

	//Create WP account
	$userData = array(
		'user_pass'     => microtime(),
		'user_login'    => $username,
		'user_nicename' => sanitize_title($person->{'display-name'}),
		'user_email'    => $person->email,
		'display_name'  => $person->{'display-name'},
		'first_name'    => $person->{'first-name'},
		'last_name'     => $person->{'last-name'},
		'role'		=> strtolower(get_option('crowd_account_type'))
	);

	$result = wp_insert_user($userData);

	return $result;
}

function getUserInfo($username) {

	$response = \Httpful\Request::get(get_option('crowd_url') . '/rest/usermanagement/1/user?username='.$username)
			->withXAtlassianToken('no-check')
      ->expectsJson()
			->addHeader('User-Agent', 'Wordpress')
      ->authenticateWith(get_option('crowd_app_name'), get_option('crowd_app_password'))
      ->send();
	return $response->body;
}

//Temporary fix for e-mail exists bug
if ( !function_exists('get_user_by_email') ) :
/**
 * Retrieve user info by email.
 *
 * @since 2.5
 *
 * @param string $email User's email address
 * @return bool|object False on failure, User DB row object
 */
function get_user_by_email($email) {
	if(strlen($email) == 0 || empty($email) || $email == '' || strpos($email, '@') == false) {
		return false;
	} else {
		return get_user_by('email', $email);
	}
}
endif;

register_activation_hook( __FILE__, 'crowd_activation_hook' );
?>
