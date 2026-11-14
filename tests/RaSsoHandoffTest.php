<?php
/**
 * Checks for RaSsoHandoff, the rules that stop a made-up cookie logging anyone in.
 * Run with: php tests/RaSsoHandoffTest.php
 */
define('_JEXEC', 1);
require __DIR__ . '/../lib_ra_sso/utility/RaSsoHandoff.php';

$failures = 0;
function check(string $name, bool $ok): void
{
    global $failures;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . "\n";
    $failures += $ok ? 0 : 1;
}

$secret = 'site-secret-from-configuration-php';
$now = 1_800_000_000;
$state = RaSsoHandoff::newState('Ramblers');
$token = RaSsoHandoff::create(42, $state, $secret, $now);

check('a genuine hand-off names the member', RaSsoHandoff::verify($token, $state, $secret, $now) === 42);
check('it still works just before it expires', RaSsoHandoff::verify($token, $state, $secret, $now + RaSsoHandoff::SECONDS) === 42);
check('it expires', RaSsoHandoff::verify($token, $state, $secret, $now + RaSsoHandoff::SECONDS + 1) === null);
check('one from too far ahead is refused', RaSsoHandoff::verify($token, $state, $secret, $now - 10) === null);
check('another site\'s secret is refused', RaSsoHandoff::verify($token, $state, 'other', $now) === null);
check('another browser (state) is refused', RaSsoHandoff::verify($token, RaSsoHandoff::newState('Ramblers'), $secret, $now) === null);
check('no state cookie is refused', RaSsoHandoff::verify($token, '', $secret, $now) === null);
check('no site secret is refused', RaSsoHandoff::verify($token, $state, '', $now) === null);

[$id, $exp, $nonce, $sig] = explode('.', $token);
check('changing the member is refused', RaSsoHandoff::verify("1.$exp.$nonce.$sig", $state, $secret, $now) === null);
check('changing the expiry is refused', RaSsoHandoff::verify("$id." . ($exp + 60) . ".$nonce.$sig", $state, $secret, $now) === null);
check('the old plain user ID cookie is refused', RaSsoHandoff::verify(base64_encode('42'), $state, $secret, $now) === null);
check('rubbish is refused', RaSsoHandoff::verify('a.b.c.d', $state, $secret, $now) === null);
check('a non-string is refused', RaSsoHandoff::verify(['x'], $state, $secret, $now) === null);
check('hand-offs differ each time', RaSsoHandoff::create(42, $state, $secret, $now) !== $token);
try {
    RaSsoHandoff::create(42, $state, '', $now);
    check('no hand-off without a site secret', false);
} catch (InvalidArgumentException $e) {
    check('no hand-off without a site secret', true);
}

check('the state carries the app name', RaSsoHandoff::appFromState($state) === 'Ramblers');
check('states are random', RaSsoHandoff::newState('Ramblers') !== $state);
check('the old base64 app-name state is not ours', RaSsoHandoff::appFromState(base64_encode('Ramblers')) === '');
check('the state matches its cookie', RaSsoHandoff::stateMatches($state, $state));
check('another state does not match', !RaSsoHandoff::stateMatches($state, RaSsoHandoff::newState('Ramblers')));
check('no cookie does not match', !RaSsoHandoff::stateMatches('', $state) && !RaSsoHandoff::stateMatches(null, $state));
check('no state does not match', !RaSsoHandoff::stateMatches($state, null));
check('an old-style state does not match even with a cookie', !RaSsoHandoff::stateMatches(base64_encode('Ramblers'), base64_encode('Ramblers')));

$root = 'https://www.example.org.uk/';
check('a page on the site is kept', RaSsoHandoff::returnUrl('https://www.example.org.uk/walks?x=1', $root) === 'https://www.example.org.uk/walks?x=1');
check('the backend is kept', RaSsoHandoff::returnUrl('https://www.example.org.uk/administrator/index.php', $root) === 'https://www.example.org.uk/administrator/index.php');
check('another site goes home', RaSsoHandoff::returnUrl('https://evil.example/', $root) === 'https://www.example.org.uk/index.php');
check('a look-alike host goes home', RaSsoHandoff::returnUrl('https://www.example.org.uk.evil.example/', $root) === 'https://www.example.org.uk/index.php');
check('a user-info trick goes home', RaSsoHandoff::returnUrl('https://www.example.org.uk@evil.example/', $root) === 'https://www.example.org.uk/index.php');
check('a protocol-relative URL goes home', RaSsoHandoff::returnUrl('//evil.example/', $root) === 'https://www.example.org.uk/index.php');
check('http instead of https goes home', RaSsoHandoff::returnUrl('http://www.example.org.uk/walks', $root) === 'https://www.example.org.uk/index.php');
check('a backslash goes home', RaSsoHandoff::returnUrl('https://www.example.org.uk/\\evil', $root) === 'https://www.example.org.uk/index.php');
check('a header break goes home', RaSsoHandoff::returnUrl("https://www.example.org.uk/\r\nX: y", $root) === 'https://www.example.org.uk/index.php');
check('nothing goes home', RaSsoHandoff::returnUrl('', $root) === 'https://www.example.org.uk/index.php');
check('a page relative to the site is made full', RaSsoHandoff::returnUrl('index.php?Itemid=12', $root) === 'https://www.example.org.uk/index.php?Itemid=12');
check('a path on the site is made full', RaSsoHandoff::returnUrl('/walks/programme', $root) === 'https://www.example.org.uk/walks/programme');
check('a relative page in a subfolder site', RaSsoHandoff::returnUrl('index.php?Itemid=3', 'https://example.org/group/') === 'https://example.org/group/index.php?Itemid=3');
check('a path outside a subfolder site goes home', RaSsoHandoff::returnUrl('/other/page', 'https://example.org/group/') === 'https://example.org/group/index.php');
check('javascript: goes home', RaSsoHandoff::returnUrl('javascript:alert(1)', $root) === 'https://www.example.org.uk/index.php');

check('the login form\'s menu-item return is used', RaSsoHandoff::formReturn(base64_encode('index.php?Itemid=12'), $root) === 'https://www.example.org.uk/index.php?Itemid=12');
check('the login form\'s full-URL return is used', RaSsoHandoff::formReturn(base64_encode('https://www.example.org.uk/my-account'), $root) === 'https://www.example.org.uk/my-account');
check('a return to the home page is kept', RaSsoHandoff::formReturn(base64_encode('https://www.example.org.uk/index.php'), $root) === 'https://www.example.org.uk/index.php');
check('a return to another site is not used', RaSsoHandoff::formReturn(base64_encode('https://evil.example/'), $root) === '');
check('an empty return is not used', RaSsoHandoff::formReturn('', $root) === '' && RaSsoHandoff::formReturn(base64_encode(''), $root) === '');
check('a return that isn\'t base64 is not used', RaSsoHandoff::formReturn('not base64!', $root) === '');

echo $failures === 0 ? "\nAll passed\n" : "\n$failures failed\n";
exit($failures === 0 ? 0 : 1);
