# OAuthLogin MediaWiki Extension

A lightweight MediaWiki extension that adds a "Log in with OAuth" button and authenticates users against an external OAuth 2.0 / OpenID Connect provider. Provider identities are bound to local accounts by the provider's stable `sub` claim, accounts are auto-created through MediaWiki's AuthManager, and the authorization flow uses `state` plus PKCE (S256).

## Requirements
- MediaWiki 1.41 or newer
- PHP 7.4 or newer
- An OAuth 2.0 / OIDC provider from Glitchdata that exposes Authorization, Token, and UserInfo endpoints. The UserInfo response must include a stable `sub` claim; `email`, `email_verified`, `preferred_username` and `name` are used when present.

## Installation
1) Copy or clone this extension into `extensions/OAuthLogin` in your MediaWiki install.
2) Enable it in `LocalSettings.php`:

```php
wfLoadExtension( 'OAuthLogin' );

$wgOAuthLoginClientID = 'your-client-id';
$wgOAuthLoginClientSecret = 'your-client-secret';
$wgOAuthLoginAuthURL = 'https://idp.example.com/oauth/authorize';
$wgOAuthLoginTokenURL = 'https://idp.example.com/oauth/token';
$wgOAuthLoginUserInfoURL = 'https://idp.example.com/oauth/userinfo';
$wgOAuthLoginRedirectURI = 'https://wiki.example.com/index.php/Special:OAuthLogin';
$wgOAuthLoginScope = 'openid email profile';
$wgOAuthLoginAutoCreate = true;          // create local accounts for new identities
$wgOAuthLoginLinkByEmail = false;        // see "Linking existing accounts"
$wgOAuthLoginAllowedDomains = [];        // e.g. [ 'example.com' ]; empty allows all
$wgOAuthLoginRememberMe = true;          // long-lived session cookie
```

3) Register `$wgOAuthLoginRedirectURI` with your provider. It must be the plain URL of `Special:OAuthLogin`; the callback is detected by the `code` and `state` query parameters.
4) If your wiki removes `createaccount` from anonymous users (private wiki), grant `autocreateaccount` instead so AuthManager can create accounts:

```php
$wgGroupPermissions['*']['autocreateaccount'] = true;
```

## How it works
- Anonymous users see a "Log in with OAuth" entry in the user menu linking to `Special:OAuthLogin`.
- The special page stores a random `state`, a PKCE code verifier and a timestamp in the session, then redirects to the provider.
- On return the `state` must match, be unused, and be under ten minutes old. The code is exchanged for a token with the PKCE verifier, the UserInfo endpoint is called, and the user is resolved as described below.
- Login resets the session ID, sets the user, and fires `UserLoggedIn`. The browser is then redirected to the page it came from (`returnto`) or the main page.

## Account resolution
1. If a local account is already bound to the provider `sub` (stored as the `oauthlogin-sub` user preference), that account is logged in.
2. Otherwise, if `$wgOAuthLoginLinkByEmail` is true and the provider reports `email_verified: true`, an existing account whose *confirmed* email matches exactly is bound and logged in. Ambiguous matches and accounts already bound to another `sub` are skipped.
3. Otherwise, if `$wgOAuthLoginAutoCreate` is true, a new account is created via `AuthManager::autoCreateUser`. The username comes from `preferred_username`, then the local part of `email`, then a prefix of `sub`. If that name is taken a numeric suffix is appended; an existing account is never logged into just because its name matches.
4. Otherwise login is refused.

Email is stored on new accounts when supplied and marked confirmed only when the provider reports `email_verified: true`. `$wgOAuthLoginAllowedDomains` requires a verified email on a listed domain.

## Linking existing accounts
Accounts that predate the extension have no `sub` binding. Either enable `$wgOAuthLoginLinkByEmail` (only if you trust the provider's email verification), or set the binding manually, for example with `maintenance/run.php userOptions --user Alice oauthlogin-sub --new <sub>`.

## Notes and limitations
- Outbound HTTPS from the server to the provider is required.
- The flow is a server-side confidential client; the client secret never reaches the browser.
- No refresh tokens or provider logout are handled.

## Testing
- Log out, visit `Special:OAuthLogin`, and complete the provider login. Confirm you return to the wiki logged in and that `Special:Log/newusers` shows the auto-created account.
- Log in again with the same provider identity and confirm the same local account is used.
- With `$wgOAuthLoginAllowedDomains` set, try an email on another domain and confirm access is denied.
- Reload the callback URL after a successful login and confirm the state error is shown rather than a second login.
