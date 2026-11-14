<?php

/**
 * @package    Joomla.System
 * @subpackage plg_system_ra_sso
 *
 * @author    East Cheshire Ramblers
 * @copyright Copyright (C) 2026 East Cheshire Ramblers. Based on original work Copyright (C) 2015 miniOrange.
 * @license   GNU General Public License version 3; see LICENSE.txt
 */

// no direct access
defined('_JEXEC') or die('Restricted access');

use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Factory;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Session\Session;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\Installer\Installer;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Version;

jimport('joomla.plugin.plugin');
jimport('ra_sso.utility.RaSsoClientHandler');
jimport('ra_sso.utility.RaSsoHandoff');

require_once JPATH_ADMINISTRATOR.DIRECTORY_SEPARATOR.'components'.DIRECTORY_SEPARATOR.'com_ra_sso'.DIRECTORY_SEPARATOR.'helpers'.DIRECTORY_SEPARATOR.'ra_sso_customer_setup.php';
require_once JPATH_ADMINISTRATOR . DIRECTORY_SEPARATOR . 'components' . DIRECTORY_SEPARATOR . 'com_ra_sso' . DIRECTORY_SEPARATOR . 'helpers' . DIRECTORY_SEPARATOR . 'ra_sso_utility.php';

class PlgSystemRa_sso extends CMSPlugin
{

    public function onAfterRender()
    {
        $app            = Factory::getApplication();
        $body           = $app->getBody();
        $tab = 0;
        $tables = RaSsoUtility::getDBObject()->getTableList();
        foreach ($tables as $table)
        {
            if (strpos($table, "ra_sso_config") !== false) {
                $tab = $table;
                break;
            }
        }

        if($tab == 0) {
            return;
        }

        $customerResult = RaSsoClientHandler::miniOauthFetchDb('#__ra_sso_config', array('id'=>'1'));
        $applicationName= isset($customerResult['appname']) ? $customerResult['appname'] : '';
        $sso_status      = isset($customerResult['sso_enable']) ? $customerResult['sso_enable'] : 0;
        // sso_enable defaults to 1 on a fresh install, before any provider has
        // actually been configured - without this, clicking the button hits
        // the [RASSO-001] "Client ID missing" error instead of doing anything useful.
        $sso_configured = !empty($customerResult['client_id']) && !empty($customerResult['app_scope']);

        $versionObj = new Version();
        $version = $versionObj->getShortVersion();

        $redirectUrlByVersion = "";
    

        if(version_compare($version, '4.0.0', '>=')) {
            $redirectUrlByVersion = "api/index.php/v1/ra-sso-login";
        }

        if ($app->isClient('administrator')) {
            // Match the Joomla backend (atum template) "Log in" button block.
            // The frontend's "user.login" marker string doesn't exist on this page.
            $isLoginPage = stripos($body, 'btn-login-submit') !== false;
            $pattern = '/(<div[^>]*class=["\']form-group["\'][^>]*>\s*<button[^>]*id=["\']btn-login-submit["\'][^>]*>.*?<\/button>\s*<\/div>)/is';
        } else {
            // task=user.login is the com_users login form's post target and is
            // present regardless of template, unlike any particular CSS class.
            $isLoginPage = stristr($body, "user.login") !== false;
            // Match the Joomla frontend com_users login "Log in" submit button
            // (skips the passkey button, which shares the same wrapper class
            // but is type="button" not type="submit").
            $pattern = '/(<div[^>]*class=["\']com-users-login__submit control-group["\'][^>]*>\s*<div[^>]*class=["\']controls["\'][^>]*>\s*<button[^>]*type=["\']submit["\'][^>]*>.*?<\/button>\s*<\/div>\s*<\/div>)/is';
        }

        if ($sso_status == 1 && $sso_configured && $isLoginPage) {
            // Where the login form would go after a password login (its hidden "return" field:
            // the menu item's login redirect, or the page that sent the member to log in). SSO
            // goes there too. Without it SSO would go back to the login page itself, which
            // guests only can see.
            $returnParam = '';
            if (!$app->isClient('administrator')
                && preg_match('#<form[^>]*com-users-login__form[^>]*>(.*?)</form>#is', $body, $form)) {
                $encoded = '';
                if (preg_match('#<input[^>]*name=["\']return["\'][^>]*value=["\']([^"\']*)["\']#i', $form[1], $field)
                    || preg_match('#<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']return["\']#i', $form[1], $field)) {
                    $encoded = html_entity_decode($field[1], ENT_QUOTES);
                }
                if (RaSsoHandoff::formReturn($encoded, Uri::root()) === '') {
                    // As Joomla's own login does when the form has nowhere set: the profile.
                    $encoded = base64_encode('index.php?option=com_users&view=profile');
                }
                $returnParam = '&return=' . rawurlencode($encoded);
            }

            // Your custom SSO login button
            $linkAddPlace = '
                <div class="form-group mt-2">
                    <a href="' . Uri::root() . $redirectUrlByVersion . '?rarequest=oauthredirect&app_name=' . rawurlencode((string) $applicationName) . htmlspecialchars($returnParam, ENT_QUOTES) . '"
                       class="btn btn-primary w-100">
                       Login with Single Sign On
                    </a>
                </div>';

            // Append custom button after Joomla login button
            $replacement = '$1' . $linkAddPlace;

            $body = preg_replace($pattern, $replacement, $body, 1); // replace once
            $app->setBody($body);
        }
    }

    public function onAfterInitialise()
    {
        $app = Factory::getApplication();
        // Get input object
        if (method_exists($app, 'getInput')) {
            $input = $app->getInput();
        } else { // Joomla 3
            $input = $app->input;
        }

        // Get all POST data
        $post = $input->post->getArray();

        $cookie = $input->cookie;

        $lang = $app->getLanguage();

        $lang->load('plg_system_ra_sso', JPATH_ADMINISTRATOR);

        // The uninstall feedback form (shown by onExtensionBeforeUninstall) uninstalls the
        // extensions it lists. Only for a backend user allowed to uninstall, from the form itself.
        if (isset($post['mojsp_feedback']) && $this->canUninstall($app) && Session::checkToken('post')) {
           
            $radio = !empty($post['deactivate_plugin']) ? $post['deactivate_plugin'] : '';
            $data = !empty($post['query_feedback']) ? $post['query_feedback'] : '';
            if(isset($post['ra_sso_feedback_skip']) && $data == '') {
                $data = 'Skipped';
            }

            if (method_exists($app, 'getIdentity')) {
                $user = $app->getIdentity();     // Joomla 4+
            } else {
                $user = Factory::getUser();      // Joomla 3
            }

            $feedback_email = !empty($post['feedback_email']) ? $post['feedback_email'] : '';

            $fields = array(
                'uninstall_feedback'=>1
            );
            $conditions = array(
                'id'=>'1'
            );

            RaSsoClientHandler::miniOauthUpdateDb('#__ra_sso_customer', $fields, $conditions);
            $customerResult= RaSsoClientHandler::miniOauthFetchDb('#__ra_sso_customer', array('id'=>'1'));
            $admin_phone = $customerResult['admin_phone'];
            $data1 = $radio . ' : ' . $data;
            include_once JPATH_SITE . DIRECTORY_SEPARATOR . 'libraries' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Installer' . DIRECTORY_SEPARATOR . 'Installer.php';
            
            foreach ((array) ($post['result'] ?? []) as $fbkey) 
            {
                $fbkey = (int) $fbkey;
                $result = RaSsoClientHandler::miniOauthFetchDb('#__extensions', array('extension_id'=>$fbkey), 'loadColumn', 'type');
                $type = 0;
                foreach ($result as $results) 
                {
                    $type = $results;
                }
                if ($type) {
                    $cid = 0;
                    $installer = new Installer();
                    $installer->setDatabase(RaSsoUtility::getDBObject()); 
                    $installer->uninstall($type, $fbkey, $cid);
                }
            }
        }

        // Cookies from before 3.1.6 named the member in plain text. Never trusted; just cleared.
        foreach (RaSsoHandoff::OLD_COOKIES as $old) {
            if ($cookie->get($old, null) !== null) {
                RaSsoHandoff::setCookie($old, '', 0);
            }
        }

        // The SSO callback runs in the API application; the member is logged in on the next
        // request, to the site (or the backend).
        $handoff = $app->isClient('api') ? '' : $cookie->getString(RaSsoHandoff::LOGIN_COOKIE, '');
        if ($handoff !== '') {
            // Used once: cleared whatever happens next.
            RaSsoHandoff::setCookie(RaSsoHandoff::LOGIN_COOKIE, '', 0);
            $state = $cookie->getString(RaSsoHandoff::STATE_COOKIE, '');
            RaSsoHandoff::setCookie(RaSsoHandoff::STATE_COOKIE, '', 0);

            if (method_exists($app, 'getSession')) {
                $session = $app->getSession();   // Joomla 4+
            } else {
                $session = Factory::getSession();// Joomla 3
            }

            $user_id = RaSsoHandoff::verify($handoff, $state, RaSsoHandoff::secret(), time());
            if ($user_id === null) {
                RaSsoLogger::addLog('SSO hand-off cookie was not genuine, or had expired', 'WARNING');
            } else {
                $user = User::getInstance($user_id);

                if (!$user->guest && $user->id && !$user->block) {
                    $response = new AuthenticationResponse();
                    $response->status = 1;
                    $response->type = 'OAuth';
                    $response->username = $user->username;
                    $response->email = $user->email;
                    $response->fullname = $user->name;

                    $app->triggerEvent(
                        'onUserLogin',
                        array(
                            (array) $response,
                            array('remember' => false)
                        )
                    );

                    $session->set('user', $user);

                    if (method_exists($app, 'loadIdentity')) {
                        $app->loadIdentity($user);
                    }

                    RaSsoClientHandler::miniOauthUpdateDb(
                        '#__session',
                        array(
                            'username' => $user->username,
                            'guest' => '0',
                            'userid' => $user->id
                        ),
                        array('session_id' => $session->getId())
                    );
                }
            }

            if ($app->isClient('administrator')) {
                // Joomla's own AdministratorApplication::findOption() would
                // block this user from any real backend page anyway once
                // they don't hold core.login.admin, but it leaves them
                // pinned on the login page with no explanation instead of
                // resetting them to guest. Do that explicitly here and send
                // them to the frontend instead.
                if (isset($user) && $user->id && !$user->authorise('core.login.admin')) {
                    $guest = new User();
                    $session->set('user', $guest);
                    if (method_exists($app, 'loadIdentity')) {
                        $app->loadIdentity($guest);
                    }
                    $app->redirect(Uri::root() . 'index.php');
                }

                $app->redirect(Uri::root() . 'administrator/index.php');
            } else {
                // This request is the page the member started SSO from (the ra_sso_return cookie
                // the login handler redirected to), so carry on to it, now logged in, rather
                // than always the home page. Only a plain GET of a page on this site;
                // anything else still goes home. The hand-off cookie is cleared above, so
                // this happens once.
                $here = Uri::getInstance()->toString();
                $back = $app->isClient('site') && $input->getMethod() === 'GET' && Uri::isInternal($here)
                        ? $here
                        : Uri::root() . 'index.php';
                $app->redirect($back);
            }
        }
    }


    function onExtensionBeforeUninstall($id)
    {
        $app = Factory::getApplication();
        if (method_exists($app, 'getInput')) {
            $input = $app->getInput();
        } else { // Joomla 3
            $input = $app->input;
        }
        $post = $input->post->getArray();
        $db = RaSsoUtility::getDBObject();
        $query = $db->getQuery(true);
        $query->select('extension_id');
        $query->from('#__extensions');
        $query->where($db->quoteName('name') . " = " . $db->quote('COM_RA_SSO'));
        $db->setQuery($query);
        $result = $db->loadColumn();
        $tables = RaSsoUtility::getDBObject()->getTableList();
        $tab = 0;
        foreach ($tables as $table) {
            if (strpos($table, "ra_sso_customer")) {
                $tab = $table;
            }
        }
        if ($tab) {
            $db = RaSsoUtility::getDBObject();
            $query = $db->getQuery(true);
            $query->select('uninstall_feedback');
            $query->from('#__ra_sso_customer');
            $query->where($db->quoteName('id') . " = " . $db->quote(1));
            $db->setQuery($query);
            $fid = $db->loadColumn();
            $tpostData = $post;
            foreach ($fid as $value) 
            {
                if ($value == 0) {
                    foreach ($result as $results) 
                    {
                        if ($results == $id) {
                            ?>
                            <div class="form-style-6 " id="form-style-6" style="display: block;">
                                <h1 class="feedback-title">
                                    <?php echo Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_TITLE'); ?>

                                    <button type="submit"
                                            name="ra_sso_feedback_skip"
                                            class="close-x"
                                            form="mojsp_feedback"
                                            formnovalidate
                                            title="<?php echo Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_SKIP_BUTTON'); ?>">
                                        ✕
                                    </button>
                                </h1>
                                <h3> <?php echo Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_WHAT_HAPPENED'); ?> </h3>
                                <form name="f" method="post" action="" id="mojsp_feedback">
                                    <input type="hidden" name="mojsp_feedback" value="mojsp_feedback"/>
                                    <?php echo HTMLHelper::_('form.token'); ?>
                                    <div>
                                        <p style="margin-left:2%">
                                        <?php
                                        $deactivate_reasons = array(
                                            Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_WHAT_HAPPENED_OPTION_1'),
                                            Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_WHAT_HAPPENED_OPTION_2'),
                                            Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_WHAT_HAPPENED_OPTION_4'),
                                            Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_WHAT_HAPPENED_OPTION_5'),
                                            Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_WHAT_HAPPENED_OPTION_7'),
                                            Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_WHAT_HAPPENED_OPTION_8'),
                                            Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_WHAT_HAPPENED_OPTION_9')
                                        );
                                        foreach ($deactivate_reasons as $deactivate_reasons) { ?>
                                        <div class=" radio " style="padding:1px;margin-left:2%;cursor:pointer">
                                            <label style="font-weight:normal;font-size:14.6px"
                                                   for="<?php echo $deactivate_reasons; ?>">
                                                <input type="radio" name="deactivate_plugin"
                                                       value="<?php echo $deactivate_reasons; ?>" required>
                                                <?php echo $deactivate_reasons; ?></label>
                                        </div>
                                        <?php } ?>
                                        <br>
                                        <textarea id="query_feedback" name="query_feedback" rows="4"
                                                  style="margin-left:2%"
                                                  cols="50" minlength="20" placeholder="<?php echo Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_QUERY_PLACEHOLDER'); ?>"></textarea><br><br><br>
                                        <tr>
                                <td width="20%"><b> <?php echo Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_EMAIL'); ?> <span style="color: #ff0000;">*</span>:</b></td>
                                <td><input type="email" name="feedback_email" required placeholder="<?php echo Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_EMAIL_PLACEHOLDER'); ?>" style="width:55%"/></td>
                                       </tr>
                                            <?php
                                            foreach ($tpostData['cid'] as $key) { ?>
                                            <input type="hidden" name="result[]" value="<?php echo (int) $key ?>">
                                            <?php } ?>
                                        <br><br>
                                        <div class="mojsp_modal-footer">
                                            <input type="submit" name="ra_sso_feedback_submit"
                                                   class="button button-primary button-large" value="<?php echo Text::_('PLG_SYSTEM_RA_SSO_FEEDBACK_FORM_SUBMIT_BUTTON'); ?>"/>
                                        </div>
                                        <br>
                                    </div>
                                </form>
                            </div>
                            <script src="https://code.jquery.com/jquery-3.6.0.min.js" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>
                            <script>
                                jQuery('input:radio[name="deactivate_plugin"]').click(function () {
                                    var reason = jQuery(this).val();
                                    jQuery('#query_feedback').removeAttr('required');
                                    if (reason == 'Facing issues During Registration') {
                                        jQuery('#query_feedback').attr("placeholder", "Can you please describe the issue in detail?");
                                    } else if (reason == "Does not have the features I'm looking for") {
                                        jQuery('#query_feedback').attr("placeholder", "Let us know what feature are you looking for");
                                    } else if (reason == "Other Reasons:") {
                                        jQuery('#query_feedback').attr("placeholder", "Can you let us know the reason for deactivation");
                                        jQuery('#query_feedback').prop('required', true);
                                    } else if (reason == "Not able to Configure") {
                                        jQuery('#query_feedback').attr("placeholder", "Not able to Configure? let us know so that we can improve the interface");
                                    } else if (reason == "Confusing Interface") {
                                        jQuery('#query_feedback').attr("placeholder", "Confusing Interface? Reach out to us at support@ramblers-tools.org.uk, we'll help set up the plugin");
                                    } else if (reason == "Redirecting back to login page after Authentication") {
                                        jQuery('#query_feedback').attr("placeholder", "Reach out to us at support@ramblers-tools.org.uk, we'll help you resolve the issue");
                                    } else if (reason == "Bugs in the plugin") {
                                        jQuery('#query_feedback').attr("placeholder", "Kindly let us know at support@ramblers-tools.org.uk, what issues were you facing");
                                    }else if (reason == "Not Working") {
                                        jQuery('#query_feedback').attr("placeholder", "Kindly let us know at support@ramblers-tools.org.uk, which functionality of the plugin is not working for you");
                                        jQuery('#query_feedback').prop('required', true);
                                    }
                                });
                                
                                function skip(){
                                    jQuery("#myModal").css("display","none");
                                    jQuery('#form-style-6').css("display","block");
                                }
                            </script>
                            <style type="text/css">
                                .form-style-6 {
                                    font: 95% Arial, Helvetica, sans-serif;
                                    max-width: 400px;
                                    margin: 10px auto;
                                    padding: 16px;
                                    background: #F1F4F8;
                                    display: none;
                                }
                                .form-style-6 h1 {
                                    background: #1F3047;
                                    padding: 20px 0;
                                    font-size: 140%;
                                    font-weight: 300;
                                    text-align: center;
                                    color: #fff;
                                    margin: -16px -16px 16px -16px;
                                }
                                .form-style-6 input[type="text"],
                                .form-style-6 input[type="date"],
                                .form-style-6 input[type="datetime"],
                                .form-style-6 input[type="email"],
                                .form-style-6 input[type="number"],
                                .form-style-6 input[type="search"],
                                .form-style-6 input[type="time"],
                                .form-style-6 input[type="url"],
                                .form-style-6 textarea,
                                .form-style-6 select {
                                    transition: all 0.30s ease-in-out;
                                    outline: none;
                                    box-sizing: border-box;
                                    width: 100%;
                                    background: #fff;
                                    margin-bottom: 4%;
                                    border: 1px solid #ccc;
                                    padding: 3%;
                                    color: #1F3047;
                                    font: 95% Arial, Helvetica, sans-serif;
                                }
                                .form-style-6 input[type="text"]:focus,
                                .form-style-6 input[type="date"]:focus,
                                .form-style-6 input[type="datetime"]:focus,
                                .form-style-6 input[type="email"]:focus,
                                .form-style-6 input[type="number"]:focus,
                                .form-style-6 input[type="search"]:focus,
                                .form-style-6 input[type="time"]:focus,
                                .form-style-6 input[type="url"]:focus,
                                .form-style-6 textarea:focus,
                                .form-style-6 select:focus {
                                    box-shadow: 0 0 5px #2E486B;
                                    border: 1px solid #2E486B;
                                    padding: 3%;
                                }
                                .form-style-6 input[type="submit"],
                                .form-style-6 input[type="button"] {
                                    box-sizing: border-box;
                                    width: 100%;
                                    padding: 3%;
                                    background: #2E486B;
                                    border-bottom: 2px solid #1F3047;
                                    border: none;
                                    color: #fff;
                                    cursor: pointer;
                                }
                                .form-style-6 input[type="submit"]:hover,
                                .form-style-6 input[type="button"]:hover {
                                    background: #36547D;
                                }
                                .feedback-title {
                                    position: relative;
                                }
                                .close-x {
                                    position: absolute;
                                    top: 50%;
                                    right: 15px;
                                    transform: translateY(-50%);
                                    background: transparent;
                                    border: none;
                                    color: #fff;
                                    font-size: 22px;
                                    font-weight: bold;
                                    cursor: pointer;
                                    padding: 0;
                                }
                                .close-x:hover {
                                    color: #ffdddd;
                                }
                            </style>
                                <?php
                                exit;
                        }
                    }
                }
            }
        }
    }

    /** A backend user allowed to uninstall extensions. */
    private function canUninstall($app): bool
    {
        if (!$app->isClient('administrator')) {
            return false;
        }
        $user = method_exists($app, 'getIdentity') ? $app->getIdentity() : Factory::getUser();
        return $user && !$user->guest && $user->authorise('core.delete', 'com_installer');
    }

    public function onAfterRoute()
    {
        $app = Factory::getApplication();

        if (method_exists($app, 'getInput')) {
            $input = $app->getInput();
        } else { // Joomla 3
            $input = $app->input;
        }

        $get = $input->get->getArray();
        if (isset($get['rarequest']) && !isset($get['morequest'])) {
            $get['morequest'] = $get['rarequest'];
        }

        $raSsoClientHandler = new RaSsoClientHandler();
        if(isset($get['morequest']) && $get['morequest'] == 'testattrmappingconfig') {
            $raSsoClientHandler->handleOAuthRequest($get);
        }
        else if(isset($get['morequest']) and $get['morequest'] == 'oauthredirect') {
            $raSsoClientHandler->handleOAuthRequest($get);
        }
        else if(isset($get['code'])) {
            $raSsoClientHandler->handleOAuthRequest($get);
        }
    }  
}
