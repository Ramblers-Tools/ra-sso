<?php
/**
 * @package    Joomla.Administrator
 * @subpackage com_ra_sso
 *
 * @author    East Cheshire Ramblers
 * @copyright Copyright (C) 2026 East Cheshire Ramblers. Based on original work Copyright (C) 2015 miniOrange.
 * @license   GNU General Public License version 3; see LICENSE.txt
 */
 
defined('_JEXEC') or die('Restricted access');
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;

require_once __DIR__ . '/ra_sso_logger.php';
require_once __DIR__ . '/ra_sso_utility.php';

$language = Factory::getLanguage();
$language->load('com_ra_sso', JPATH_ADMINISTRATOR, null, false, true);

class RaSsoHandler
{
    public $error;
    function __construct($error='')
    {
        $this->error=$error;
    }

    function getAccessToken($tokenendpoint, $grant_type, $clientid, $clientsecret, $code, $redirect_url,$in_header_or_body)
    {
        if(!RaSsoUtility::is_curl_installed()) {
            return json_encode(array("status"=>'CURL_ERROR','statusMessage'=>'<a href="http://php.net/manual/en/curl.installation.php">PHP cURL extension</a> is not installed or disabled.'));
        }

        $session = Factory::getSession();
        if (!self::isHttpsUrl($tokenendpoint)) {
            RaSsoLogger::addLog('Error : the token endpoint is not https', 'CRITICAL', 'RASSO-A02');
            $this->setError('[RASSO-A02] : ' . Text::_('COM_RA_SSO_ENDPOINT_NOT_HTTPS'));
            $session->set('mo_reason', 'The token endpoint must use https.');
            return array('', '');
        }
        $ch = curl_init($tokenendpoint);
        if (defined('CURLOPT_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        }
        // The token request carries the client secret: never follow a redirect with it, and
        // always check the provider's certificate (the answer decides who is logged in).
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_ENCODING, "");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_POST, true);
        
        if($in_header_or_body=='both') {
            curl_setopt(
                $ch, CURLOPT_HTTPHEADER, array(
                'Accept: application/json',
                'Authorization: Basic ' . base64_encode($clientid . ":" . $clientsecret)
                )
            );
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array('redirect_uri' => $redirect_url, 'grant_type' => $grant_type, 'client_id' => $clientid, 'client_secret' => $clientsecret, 'code' => (string) $code), '', '&'));

        }
        elseif($in_header_or_body=='inHeader') {
            curl_setopt(
                $ch, CURLOPT_HTTPHEADER, array(
                'Accept: application/json',
                'Authorization: Basic ' . base64_encode($clientid . ":" . $clientsecret)
                )
            );
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array('redirect_uri' => $redirect_url, 'grant_type' => $grant_type, 'code' => (string) $code), '', '&'));
        }
        else{
            curl_setopt(
                $ch, CURLOPT_HTTPHEADER, array(
                'Accept: application/json'
                )
            );
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array('redirect_uri' => $redirect_url, 'grant_type' => $grant_type, 'client_id' => $clientid, 'client_secret' => $clientsecret, 'code' => (string) $code), '', '&'));
        }
        
        $content = curl_exec($ch);

        if(curl_error($ch)) {
            RaSsoLogger::addLog('Error : ' . curl_error($ch), 'CRITICAL', 'RASSO-A02');
            $this->setError('[RASSO-A02] : ' . curl_error($ch));
            $session->set('mo_reason', curl_error($ch));
        }

        $content =json_decode($content, true);
        if(!is_array($content)) {
            RaSsoLogger::addLog('Error Invalid Response', 'ERROR');
            $this->setError("[RASSO-009] : Invalid response received.");
            $session->set('mo_reason', 'Invalid response received.');
        }

        // first check if any error received
        if(isset($content["error_description"])) {
            RaSsoLogger::addLog('Error : ' . $content["error_description"], 'CRITICAL', 'RASSO-A03');
            $this->setError("[RASSO-A03] : " . $content["error_description"]);
            $session->set('mo_reason', $content["error_description"]);

        } else if(isset($content["error"])) {
            RaSsoLogger::addLog('Error : ' . $content["error"], 'CRITICAL', 'RASSO-A04');
            $this->setError("[RASSO-A04] : " . $content["error"]);
            $session->set('mo_reason',  $content["error"]);
        }
        // extract access_token and id_token
        $idToken=isset($content["id_token"])?$content["id_token"]:'';
        $access_token=isset($content["access_token"])?$content["access_token"]:'';
        if(empty($idToken) && empty($access_token)) {
            RaSsoLogger::addLog('Error Invalid Response', 'ERROR');
            $this->setError('[RASSO-009] : ' . Text::_('COM_RA_SSO_ACCESS_ID_TOKEN_MISSING') . Text::_('COM_RA_SSO_ACCESS_ID_TOKEN_MISSING_SOLUTION'));
            $session->set('mo_reason', 'Invalid response received from OAuth Provider. Contact your administrator for more details.');
        }
        
        return array($access_token,$idToken);
    }
    
    /**
     * The member's details from the ID token. The token came straight from the provider's token
     * endpoint over a checked TLS connection, which OpenID Connect allows in place of checking its
     * signature (Core 3.1.3.7); it must still be for this site (aud) and not have expired (exp).
     */
    function getResourceOwnerFromIdToken($id_token, $clientId = null)
    {
        $session = Factory::getSession();
        $claims = self::idTokenClaims($id_token, $clientId, time());
        if (is_array($claims)) {
            return $claims;
        }
        RaSsoLogger::addLog('Error Invalid ID token: ' . $claims, 'ERROR');
        $this->setError('[RASSO-009] : ' . Text::_('COM_RA_SSO_INVALID_ID_TOKEN'));
        $session->set('mo_reason', 'Invalid response received.');
        return false;
    }

    /** True for an absolute https:// address with a host. The provider's answers decide who is
     *  logged in, and the token request carries the client secret, so plain http is refused. */
    static function isHttpsUrl($url): bool
    {
        if (!is_string($url) || $url === '' || preg_match('/[\x00-\x20\\\\]/', $url)) {
            return false;
        }
        $parts = parse_url($url);
        return is_array($parts) && isset($parts['scheme'], $parts['host'])
            && strtolower($parts['scheme']) === 'https' && $parts['host'] !== '';
    }

    /** True only when the provider says the email address is verified (true, 1, "1" or "true").
     *  Accounts are found by email, so a missing or unclear answer is not enough. */
    static function emailVerified($claims): bool
    {
        if (!is_array($claims) || !array_key_exists('email_verified', $claims)) {
            return false;
        }
        $value = $claims['email_verified'];
        return $value === true || $value === 1 || $value === '1' || (is_string($value) && strtolower($value) === 'true');
    }

    /** The ID token's claims, or why it can't be used. Plain PHP, for tests. */
    static function idTokenClaims($id_token, $clientId, int $now)
    {
        $parts = is_string($id_token) ? explode('.', $id_token) : array();
        if (count($parts) !== 3) {
            return 'not a JWT';
        }
        $body = base64_decode(strtr($parts[1], '-_', '+/') . str_repeat('=', (4 - strlen($parts[1]) % 4) % 4), true);
        $claims = $body === false ? null : json_decode($body, true);
        if (!is_array($claims)) {
            return 'unreadable';
        }
        if ($clientId !== null && $clientId !== '') {
            $aud = isset($claims['aud']) ? (array) $claims['aud'] : array();
            if (!in_array((string) $clientId, array_map('strval', $aud), true)) {
                return 'not for this client';
            }
        }
        if (!isset($claims['exp']) || !is_numeric($claims['exp']) || (int) $claims['exp'] < $now - 300) {
            return 'expired';
        }
        return $claims;
    }

    function getResourceOwner($resourceownerdetailsurl, $access_token,$idToken, $clientId = null)
    {
        $session = Factory::getSession();
        if(!RaSsoUtility::is_curl_installed()) {
            return json_encode(array("status"=>'CURL_ERROR','statusMessage'=>'<a href="http://php.net/manual/en/curl.installation.php">PHP cURL extension</a> is not installed or disabled.'));
        }
        if(!empty($idToken) && !is_null($idToken)) {
            return $this->getResourceOwnerFromIdToken($idToken, $clientId);
        }
        if (!self::isHttpsUrl($resourceownerdetailsurl)) {
            RaSsoLogger::addLog('Error : the user info endpoint is not https', 'CRITICAL', 'RASSO-A02');
            $this->setError('[RASSO-A02] : ' . Text::_('COM_RA_SSO_ENDPOINT_NOT_HTTPS'));
            $session->set('mo_reason', 'The user info endpoint must use https.');
            return array();
        }
        $ch = curl_init($resourceownerdetailsurl);
        if (defined('CURLOPT_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        }
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_ENCODING, "");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_AUTOREFERER, true);
        // The answer decides who is logged in: always check the provider's certificate, and
        // only follow redirects to https.
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        if (defined('CURLOPT_REDIR_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
        }
        curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
        curl_setopt($ch, CURLOPT_POST, false);
        curl_setopt(
            $ch, CURLOPT_HTTPHEADER, array(
            'Authorization: Bearer '.$access_token,
            'User-Agent:web'
            )
        );    
        $content = curl_exec($ch);
        
        if(curl_error($ch)) {
            $this->setError(curl_error($ch));
            $session->set('mo_reason', curl_error($ch));
            return false;
        }
        $content = json_decode($content, true);
        if(!is_array($content)) {
            RaSsoLogger::addLog('Error Invalid Response', 'ERROR');
            $this->setError("[RASSO-009] : " . Text::_('COM_RA_SSO_INVALID_RESPONSE'));
            $session->set('mo_reason', "Invalid response received.");
            return false;
        }
        
        if(isset($content["error_description"])) {
            RaSsoLogger::addLog('Error Invalid Response', 'ERROR');
            $this->setError('[RASSO-009] : ' . $content["error_description"]);
            $session->set('mo_reason', '[RASSO-009]' .$content["error_description"]);
            return false;
        } else if(isset($content["error"])) {
            RaSsoLogger::addLog('Error Invalid Response', 'ERROR');
            $this->setError('[RASSO-009] : '. $content["error"]);
            $session->set('mo_reason', '[RASSO-009 : ]'. $content["error"]);
            return false;
        } 
        return $content;
    }

    function base64url_decode($data) 
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }
        $data = strtr($data, '-_', '+/');
        return base64_decode($data);
    }

    function setError($error)
    {
        $this->error=$error;
    }
    
    function isError()
    {
        if(empty($this->error)) {
            return false;
        }
        return true;
    }

    function printError()
    {
        if(!$this->isError()) {
            return;
        }

        // Error text can come from the provider: never print it as HTML.
        if(is_array($this->error)) {
            echo htmlspecialchars(print_r($this->error, true), ENT_QUOTES, 'UTF-8');
        } else {
            echo htmlspecialchars((string) $this->error, ENT_QUOTES, 'UTF-8');
        }

        echo Text::_('COM_RA_SSO_LOGS_SUGGESTION');
        exit;
    }

    function showFormattedErrorMessage(string $errorMessage, string $description = '')
    {
        $body = "<p style='margin:0 0 10px; font-weight:bold; font-size:16px;'>" . htmlspecialchars($errorMessage) . "</p>";

        if (!empty($description)) {
            $body .= "<p style='margin:5px 0;'>" . nl2br(htmlspecialchars($description)) . "</p>";
        }

        echo "
        <div style='
            background: #fff;
            padding: 18px;
            border-radius: 8px;
            border: 2px solid #cc3333;
            box-shadow: 0 0 12px rgba(0,0,0,0.18);
            margin-top: 15px;
            font-family: Arial, sans-serif;
        '>
            <div style='font-size:14px; color:#333; line-height:1.5;'>
                $body
            </div>
        </div>
        ";
    }
}