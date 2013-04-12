<?php
/*
Plugin Name: Restricted Access
Plugin URI: http://pathartl.me/5463/restricted-access-wordpress-plugin
Description: Only allows users that have the appropriate role to visit the site
Author: Pat Hartl
Version: 1.0
Author URI: http://pathartl.me
License: GPL2
*/

$restricted_access_option_name = 'restricted-access';

//---------------------------------------------------//
// All dashboard pages handled below
//---------------------------------------------------//

add_action('admin_menu', 'restricted_access_add_page');

function restricted_access_add_page() {
	add_users_page('Restricted Access Options', 'Restricted Access', 'manage_options', 'restricted_access_options', 'restricted_access_options_do_page');
}

// Generates checkbox inputs listing the roles
// $input_name parameter is the name parameter of the form element
// $checked_roles should be an array of role slugs that will be prechecked
// Example input: restricted_access_role_selector("allowed_roles")
// Output: <input type="checkbox" name="allowed_roles[]" value="administrator" />
function restricted_access_role_selector($input_name, $checked_roles) {
	global $wp_roles;

	// The display name of the role, not the slug
	$role_display_name = array_values($wp_roles->get_names());

	// The role slug
	$role_slug_name = array_keys($wp_roles->get_names());

	// We could have used foreach I guess, but I don't think it's as convienent.
	for ($i = 0; $i < count($role_display_name); $i++) {
		// Check if our role has been checked and saved
		if ( count($checked_roles) && in_array($role_slug_name[$i], $checked_roles) ) {
			$checked = 'checked="yes"';
		} else {
			$checked = '';
		}

		// Do the HTML
		echo '<label>';
		echo '<input type="checkbox" name="' . $input_name . '[]" value="' . $role_slug_name[$i] . '" ' . $checked . ' /> ';
		echo $role_display_name[$i] . '</label><br>';
	}

}

// Print the menu page itself
function restricted_access_options_do_page() {
	global $restricted_access_option_name;
	$options = get_option($restricted_access_option_name);

	if ( isset($_POST['allowed_roles']) && isset($_POST['denied_roles']) ) {
		$options['restricted-access-allowed'] = array_map('esc_attr', $_POST['allowed_roles']);
		$options['restricted-access-denied'] = array_map('esc_attr', $_POST['denied_roles']);
		$options['restricted-access-lock-site'] = isset($_POST['lock_site']);

		update_option($restricted_access_option_name, $options);

		// Give the users a notice that the settings have been saved
		echo '<div class="updated"><p>Your settings have been saved!</p></div>';
	}
?>

	<div class="wrap">
		<h2>Restricted Access Options</h2>
		<h3>Role Filters</h3>
		<form method="post" action="users.php?page=restricted_access_options">
			Enter the roles that you would like to allow or deny on your site in the fields below (comma separated e.g. "administrator,editor,author")
			<table class="form-table">
				<tr valign="top"><th scope="row">Allowed Roles:</th>
					<td><?php restricted_access_role_selector('allowed_roles', $options['restricted-access-allowed']); ?></td>
				</tr>
				<tr valign="top"><th scope="row">Denied Roles:</th>
					<td><?php restricted_access_role_selector('denied_roles', $options['restricted-access-denied']); ?></td>
				</tr>
				<tr valign="top"><th scope="row">Lock site?</th>
				<td><input type="checkbox" name="lock_site" value="1" <?php checked($options['restricted-access-lock-site']); ?>></td>
				</tr>
			</table>
			<p class="submit">
				<input type="submit" class="button-primary" value="Save Changes" />
			</p>
		</form>
		Developed by <a href="http://pathartl.me">Pat Hartl</a> and <a href="http://joshbetz.com">Josh Betz</a>
	</div>
	
<?php
}

// Listen for the activate event
register_activation_hook(__FILE__, 'restricted_access_activate');
register_deactivation_hook(__FILE__, 'restricted_access_deactivate');

function restricted_access_activate() {
	add_option($restricted_access_option_name);
}

function restricted_access_deactivate() {
	delete_option($restricted_access_option_name);
}

//---------------------------------------------------//
// Page Metaboxes
//---------------------------------------------------//

// Custom Meta Fields
add_action( 'load-post.php', 'restricted_access_meta_boxes_setup' );
add_action( 'load-post-new.php', 'restricted_access_meta_boxes_setup' );

function restricted_access_meta_boxes_setup() {

	// Add the meta boxes using add_meta_boxes()
	add_action( 'add_meta_boxes', 'restricted_access_add_meta_boxes' );

	// Save Meta
	add_action( 'save_post', 'save_restricted_access_meta_box', 10, 2 );

}

function restricted_access_add_meta_boxes() {
	add_meta_box(
		'restricted-access-lock-page',
		esc_html__( 'Lock Page', 'example' ),
		'restricted_access_meta_box',
		'page',
		'side',
		'default'
	);
}

function restricted_access_meta_box($object, $box) { ?>
<?php
	wp_nonce_field( basename( __FILE__ ), 'restricted_access_lock_page_nonce' ); ?>

  <p>
	<input type="checkbox" <?php if (get_post_meta( $object->ID, 'restricted_access_lock_page', true )) echo 'checked="yes"'; ?> name="restricted-access-lock-page" value="yes" />
	<label for="restricted-access-lock-page">&nbsp;<?php _e( "Lock this page?", 'example' ); ?></label>
  </p>
<?php }

/* Save the meta box's post metadata. */
function save_restricted_access_meta_box( $post_id, $post ) {

	/* Verify the nonce before proceeding. */
	if ( !isset( $_POST['restricted_access_lock_page_nonce'] ) || !wp_verify_nonce( $_POST['restricted_access_lock_page_nonce'], basename( __FILE__ ) ) )
		return $post_id;

	/* Get the post type object. */
	$post_type = get_post_type_object( $post->post_type );

	/* Check if the current user has permission to edit the post. */
	if ( !current_user_can( $post_type->cap->edit_post, $post_id ) )
		return $post_id;

	/* Get the posted data and sanitize it for use as an HTML class. */
	$new_meta_value = ( isset( $_POST['restricted-access-lock-page'] ) ? sanitize_html_class( $_POST['restricted-access-lock-page'] ) : '' );

	/* Get the meta key. */
	$meta_key = 'restricted_access_lock_page';

	/* Get the meta value of the custom field key. */
	$meta_value = get_post_meta( $post_id, $meta_key, true );

	/* If a new meta value was added and there was no previous value, add it. */
	if ( $new_meta_value && '' == $meta_value )
		add_post_meta( $post_id, $meta_key, $new_meta_value, true );

	/* If the new meta value does not match the old value, update it. */
	elseif ( $new_meta_value && $new_meta_value != $meta_value )
		update_post_meta( $post_id, $meta_key, $new_meta_value );

	/* If there is no new meta value but an old value exists, delete it. */
	elseif ( '' == $new_meta_value && $meta_value )
		delete_post_meta( $post_id, $meta_key, $meta_value );
}

//---------------------------------------------------//
// Main Logic
//---------------------------------------------------//

function restricted_access_protect_whole_site() {
	global $post, $restricted_access_option_name;

	// Guilty until proven innocent?
	$allowed = false;

	// Get our options
	$options = get_option($restricted_access_option_name);

	// Check if user is not logged in and if the page is locked or the whole site is locked
	// This just checks to see if a user is logged in. Any checking of their role is done after the else
	if ( !is_user_logged_in() && ((get_post_meta($post->ID, 'restricted_access_lock_page', TRUE) || ($options['restricted-access-lock-site'])) ) ) {
		// Ask user to log in
		wp_safe_redirect(network_site_url('/wp-login.php?redirect_to=' . get_site_url()));
		// NOTE: This will do authentication through the main network site if this is a network install
		// We do this to better work with plugins like Active Directory Integration

	} elseif(is_user_logged_in()) {
		// Let's check some roles
		// Get role from main site in WPMU
		$user_role = get_user_meta(get_current_user_id(), 'wp_capabilities');
		$user_role = array_keys($user_role[0]);

		//$allowed_roles = explode(',', $options['restricted-access-allowed'])

		$allowed_roles = $options['restricted-access-allowed'];
		$denied_roles = $options['restricted-access-denied'];

		// We'll check the user's role to see if it's allowed
		if (!empty($options['restricted-access-allowed'])) {
			foreach ($allowed_roles as $role) {
				if($user_role[0] == $role) {
					// Open the gates!
					$allowed = true;
				}
			}
		}



		// If we have some denied roles and no allowed roles...
		if (!empty($options['restricted-access-denied']) && empty($options['restricted-access-allowed'])) {
			$allowed = true;
			// Check each denied role for our user's role
			foreach ($denied_roles as $role) {
				if($user_role[0] == $role) {
					// If we have a role that matches, block that shit
					$allowed = false;
				}
			}
		}

		if ( !get_post_meta($post->ID, 'restricted_access_lock_page', TRUE) && !($options['restricted-access-lock-site']) )
			$allowed = true;

		// If our criteria was not met, redirect!
		if ($allowed == false && !is_page( 'access-denied' ) ) {
			wp_safe_redirect(bloginfo('url') . '/access-denied?role=' . $user_role[0]);
		}
	}
}

add_action('template_redirect', 'restricted_access_protect_whole_site');

?>
