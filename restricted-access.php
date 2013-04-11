<?php
/*
Plugin Name: Restricted Access
Plugin URI: http://pathartl.me/5463/restricted-access-wordpress-plugin
Description: When enabled, only allows users that have the appropriate role are allowed to visit the site
Author: Pat Hartl
Version: 1.0
Author URI: http://pathartl.me
License: GPL2
*/

$option_name = 'restricted-access';

add_action('admin_init', array($this, 'admin_init'));

function admin_init() {
	register_setting('restricted_access_options', $option_name, 'validate');
}

// Sanitize our input
function validate($input) {
	$valid = array();
	$valid['allowed_roles'] = sanitize_text_field($input['allowed_roles']);
	$valid['denied_roles'] = sanitize_text_field($input['denied_roles']);
	$valid['lock_site'] = sanitize_text_field($input['lock_site']);

	return $valid;
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
// All dashboard pages handled below
//---------------------------------------------------//

 add_action('admin_menu', 'add_page');

 function add_page() {
 	add_users_page('Restricted Access Options', 'Restricted Access', 'manage_options', 'restricted_access_options', 'options_do_page');
 }


// Print the menu page itself
function options_do_page() {
    $options = get_option($option_name);
    if ( isset($_POST['allowed_roles']) && isset($_POST['denied_roles']) ) {
    	update_option('restricted-access-allowed', $_POST['allowed_roles']);
    	update_option('restricted-access-denied', $_POST['denied_roles']);
    	update_option('restricted-access-lock-site', $_POST['lock_site']);
    }
    ?>
    <div class="wrap">
        <h2>Restricted Access Options</h2>
        <h3>Role Filters</h3>
        <form method="post" action="users.php?page=restricted_access_options">
        	Enter the roles that you would like to allow or deny on your site in the fields below (comma separated e.g. "administrator,editor,author")
            <table class="form-table">
                <tr valign="top"><th scope="row">Allowed Roles:</th>
                    <td><input type="text" size="60" name="allowed_roles" value="<?php echo get_option('restricted-access-allowed'); ?>" /></td>
                </tr>
                <tr valign="top"><th scope="row">Denied Roles:</th>
                    <td><input type="text" size="60" name="denied_roles" value="<?php echo get_option('restricted-access-denied'); ?>" /></td>
                </tr>
                <tr valign="top"><th scope="row">Lock site?</th>
                    <td><input type="checkbox" <?php if (get_option('restricted-access-lock-site')) echo 'checked="yes"'; ?> name="lock_site" value="yes" /></td>
                </tr>
            </table>
            <p class="submit">
                <input type="submit" class="button-primary" value="Save Changes" />
            </p>
        </form>
        Developed by <a href="http://pathartl.me">Pat Hartl</a>
    </div>
<?php
}

// Listen for the activate event
register_activation_hook(RESTRICTED_ACCESS, 'activate');

function activate() {
	update_option('restricted-access-allowed', '');
	update_option('restricted-access-denied', '');
	update_option('restricted-access-lock-site', '');
}

function deactivate() {
	delete_option('restricted-access-allowed');
	delete_option('restricted-access-denied');
	delete_option('restricted-access-lock-site');
}

//---------------------------------------------------//
// Main Logic
//---------------------------------------------------//

function protect_whole_site() {
	global $post;
	// Guilty until proven innocent?
	$allowed = false;

	// Check if user is not logged in and if the page is locked or the whole site is locked
	// This just checks to see if a user is logged in. Any checking of their role is done after the else
    if ( !is_user_logged_in() && (get_post_meta($post->ID, 'restricted_access_lock_page', TRUE) || (get_option('restricted-access-lock-site') == "yes") ) ) {
    	// Ask user to log in
        wp_safe_redirect(network_site_url('/wp-login.php?redirect_to=' . get_site_url()));
        // NOTE: This will do authentication through the main network site if this is a network install
        // We do this to better work with plugins like Active Directory Integration

    } else {
    	// Let's check some roles
    	// Get role from main site in WPMU
		$user_role = get_user_meta(get_current_user_id(), 'wp_capabilities');
		$user_role = array_keys($user_role[0]);

		//$allowed_roles = explode(',', get_option('restricted-access-allowed'))


		// Get our options
		$options['allowed_roles'] = get_option('restricted-access-allowed');
		$options['denied_roles'] = get_option('restricted-access-denied');
		$options['lock_site'] = get_option('restricted-access-lock-site');

		$allowed_roles = explode(",", $options['allowed_roles']);
		$denied_roles = explode(",", $options['denied_roles']);
		$lock_site = explode(",", $options['lock_site']);

		// We'll check the user's role to see if it's allowed
		if ($options['allowed_roles'] != '') {
			foreach ($allowed_roles as $role) {
				if($user_role[0] == $role) {
					// Open the gates!
					$allowed = true;
				}

			}
		}

		// If we have some denied roles and no allowed roles...
		if (($options['denied_roles'] != '') && ($options['allowed_roles'] == '')) {
			$allowed = true;
			// Check each denied role for our user's role
			foreach ($denied_roles as $role) {
				if($user_role[0] == $role) {
					// If we have a role that matches, block that shit
					$allowed = false;
				}

			}
		}

		if ( !get_post_meta($post->ID, 'restricted_access_lock_page', TRUE) && !(get_option('restricted-access-lock-site') == "yes") ) $allowed = true;

		// If our criteria was not met, redirect!
		if ($allowed == false && !is_page( 'access-denied' ) ) {
			wp_safe_redirect(bloginfo('url') . '/access-denied?role=' . $user_role[0]);
		}
	}
}

add_action('template_redirect', 'protect_whole_site');

?>