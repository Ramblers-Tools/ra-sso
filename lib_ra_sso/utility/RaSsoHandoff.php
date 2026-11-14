<?php
/**
 * @package    Joomla.Plugin
 * @subpackage lib_ra_sso
 *
 * @author    East Cheshire Ramblers
 * @copyright Copyright (C) 2026 East Cheshire Ramblers.
 * @license   GNU General Public License version 3; see LICENSE.txt
 *
 * The values that tie an SSO login together, and the hand-off from the SSO callback (which runs
 * in Joomla's API application, with its own session) to the site, where the member is logged in.
 *
 *  - Starting SSO makes a random state. It goes to the identity provider, and into a cookie on
 *    this browser. The callback is only accepted when the two match, so nobody can finish a
 *    login they didn't start in this browser (login CSRF).
 *  - The callback hands the member over in a cookie signed with the site's secret
 *    (configuration.php), tied to that same state cookie and valid for two minutes. The site
 *    logs nobody in from a cookie it can't verify. Before 3.1.6 the hand-off was the member's
 *    ID in a plain cookie, so anyone could set it and be logged in as anyone.
 *
 * Plain PHP apart from the cookie and secret helpers, so it can be tested on its own.
 */
defined('_JEXEC') or die('Restricted access');

class RaSsoHandoff
{
    /** Cookie with the signed hand-off from the callback to the site. */
    const LOGIN_COOKIE = 'ra_sso_login';

    /** Cookie with the state of the login this browser started. */
    const STATE_COOKIE = 'ra_sso_state';

    /** Cookie with the page to go back to after SSO. */
    const RETURN_COOKIE = 'ra_sso_return';

    /**
     * Before 3.1.6 the return page was kept in "returnurl", set without a path, so it landed on
     * /api/index.php/v1 and was never cleared there. A stale one would win over a new one.
     */
    const OLD_RETURN_COOKIE = 'returnurl';
    const OLD_RETURN_PATHS = ['/', '/api/index.php/v1', '/api/index.php/v1/'];

    /** How long the hand-off works, in seconds. */
    const SECONDS = 120;

    /** How long the browser has to log in at the identity provider, in seconds. */
    const STATE_SECONDS = 1800;

    /** Cookies used by versions before 3.1.6. They're cleared, never trusted. */
    const OLD_COOKIES = ['mo_site', 'session_id', 'user_id'];

    /** A new state for a login of the given app: random, with the app name after a dot. */
    public static function newState(string $appName): string
    {
        return self::b64(random_bytes(24)) . '.' . self::b64($appName);
    }

    /** The app name carried in a state, or '' if it isn't one of ours. */
    public static function appFromState(string $state): string
    {
        $parts = explode('.', $state);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return '';
        }
        $name = self::unb64($parts[1]);
        return $name === null ? '' : $name;
    }

    /** True when the provider sent back the state this browser was given. */
    public static function stateMatches($cookie, $returned): bool
    {
        return is_string($cookie) && is_string($returned) && $cookie !== '' && strlen($cookie) <= 512
            && self::appFromState($cookie) !== '' && hash_equals($cookie, $returned);
    }

    /** A hand-off for a member, tied to this browser's state cookie. */
    public static function create(int $userId, string $state, string $secret, int $now): string
    {
        if ($userId <= 0 || $state === '' || $secret === '') {
            throw new InvalidArgumentException('Cannot make an SSO hand-off');
        }
        $payload = $userId . '.' . ($now + self::SECONDS) . '.' . self::b64(random_bytes(16));
        return $payload . '.' . self::sign($payload, $state, $secret);
    }

    /** The member a hand-off is for, or null unless it's genuine, unexpired and for this browser. */
    public static function verify($token, $state, string $secret, int $now): ?int
    {
        if (!is_string($token) || !is_string($state) || $state === '' || $secret === '' || strlen($token) > 512) {
            return null;
        }
        $parts = explode('.', $token);
        if (count($parts) !== 4) {
            return null;
        }
        [$userId, $expires, $nonce, $signature] = $parts;
        if (!ctype_digit($userId) || !ctype_digit($expires) || $nonce === '' || $signature === '') {
            return null;
        }
        $payload = $userId . '.' . $expires . '.' . $nonce;
        if (!hash_equals(self::sign($payload, $state, $secret), $signature)) {
            return null;
        }
        if ((int) $expires < $now || (int) $expires > $now + self::SECONDS) {
            return null;
        }
        return (int) $userId > 0 ? (int) $userId : null;
    }

    /** Where to go after logging in: the page SSO started from, if it's on this site. */
    public static function returnUrl($url, string $root): string
    {
        $home = rtrim($root, '/') . '/index.php';
        if (!is_string($url) || $url === '' || preg_match('/[\x00-\x1f\\\\]/', $url)) {
            return $home;
        }
        $base = rtrim($root, '/') . '/';
        return stripos($url, $base) === 0 ? $url : $home;
    }

    // -- Joomla side --------------------------------------------------------------------------

    /** The site's secret from configuration.php. */
    public static function secret(): string
    {
        return (string) \Joomla\CMS\Factory::getApplication()->get('secret', '');
    }

    /** Sets (or, with an empty value, clears) one of our cookies for the whole site. */
    public static function setCookie(string $name, string $value, int $seconds): void
    {
        setcookie($name, $value, [
            'expires' => $value === '' ? time() - 3600 : time() + $seconds,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /** Clears the pre-3.1.6 return cookie wherever it may have been set. */
    public static function clearOldReturnCookie(): void
    {
        foreach (self::OLD_RETURN_PATHS as $path) {
            setcookie(self::OLD_RETURN_COOKIE, '', ['expires' => time() - 3600, 'path' => $path, 'secure' => true, 'httponly' => true]);
            setcookie(self::OLD_RETURN_COOKIE, '', ['expires' => time() - 3600, 'path' => $path]);
        }
    }

    // -----------------------------------------------------------------------------------------

    private static function sign(string $payload, string $state, string $secret): string
    {
        return self::b64(hash_hmac('sha256', 'ra-sso-login|' . $state . '|' . $payload, $secret, true));
    }

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function unb64(string $text): ?string
    {
        if (!preg_match('/^[A-Za-z0-9_-]+$/', $text)) {
            return null;
        }
        $bytes = base64_decode(strtr($text, '-_', '+/'), true);
        return $bytes === false ? null : $bytes;
    }
}
