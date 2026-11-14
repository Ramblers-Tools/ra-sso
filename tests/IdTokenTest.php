<?php
/**
 * Checks for the ID token rules in RaSsoHandler::idTokenClaims().
 * Run with: php tests/IdTokenTest.php
 */
namespace Joomla\CMS {
    class Factory
    {
        public static function getLanguage()
        {
            return new class {
                public function load(...$args) {}
            };
        }
    }
}

namespace {
    define('_JEXEC', 1);
    define('JPATH_ADMINISTRATOR', __DIR__);
    require __DIR__ . '/../com_ra_sso/admin/helpers/oauth_handler.php';

    $failures = 0;
    function check(string $name, bool $ok): void
    {
        global $failures;
        echo ($ok ? 'ok   ' : 'FAIL ') . $name . "\n";
        $failures += $ok ? 0 : 1;
    }
    function jwt(array $claims): string
    {
        $b = fn($s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        return $b('{"alg":"RS256"}') . '.' . $b(json_encode($claims)) . '.sig';
    }

    $now = 1_800_000_000;
    $good = ['email' => 'ann@example.org', 'aud' => 'client-1', 'exp' => $now + 600];

    check('a token for this client is read', (RaSsoHandler::idTokenClaims(jwt($good), 'client-1', $now)['email'] ?? '') === 'ann@example.org');
    check('aud may be a list', is_array(RaSsoHandler::idTokenClaims(jwt(['aud' => ['x', 'client-1']] + $good), 'client-1', $now)));
    check('another client\'s token is refused', RaSsoHandler::idTokenClaims(jwt($good), 'client-2', $now) === 'not for this client');
    check('a token with no aud is refused', RaSsoHandler::idTokenClaims(jwt(['email' => 'a', 'exp' => $now + 60]), 'client-1', $now) === 'not for this client');
    check('an expired token is refused', RaSsoHandler::idTokenClaims(jwt(['exp' => $now - 301] + $good), 'client-1', $now) === 'expired');
    check('five minutes of clock difference is allowed', is_array(RaSsoHandler::idTokenClaims(jwt(['exp' => $now - 200] + $good), 'client-1', $now)));
    check('a token with no exp is refused', RaSsoHandler::idTokenClaims(jwt(['email' => 'a', 'aud' => 'client-1']), 'client-1', $now) === 'expired');
    check('rubbish is refused', is_string(RaSsoHandler::idTokenClaims('abc', 'client-1', $now)));
    check('a non-string is refused', is_string(RaSsoHandler::idTokenClaims(['x'], 'client-1', $now)));

    echo $failures === 0 ? "\nAll passed\n" : "\n$failures failed\n";
    exit($failures === 0 ? 0 : 1);
}
