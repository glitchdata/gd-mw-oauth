# OAuthLogin MediaWiki Extension

A lightweight MediaWiki extension that adds a "Log in with OAuth" button and authenticates users against an external OAuth 2.0 provider. It supports automatic account creation and optional email-domain allowlists.

## Requirements
- MediaWiki 1.39 or newer
- PHP 7.4 or newer
- An OAuth 2.0 provider that exposes Authorization, Token, and UserInfo endpoints (OpenID Connect compatible is ideal)

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
$wgOAuthLoginAutoCreate = true; // set to false to disable automatic account creation
$wgOAuthLoginAllowedDomains = [ 'example.com' ]; // optional allowlist, leave empty to allow all
```

3) Ensure the redirect URI is registered with your OAuth provider and matches `Special:OAuthLogin` on your wiki.

## How it works
- Anonymous users see a personal toolbar link that points to `Special:OAuthLogin`.
- The special page starts the OAuth authorization flow, storing a short-lived `state` in the session.
- After the provider redirects back with a `code`, the extension exchanges it for an access token, calls the UserInfo endpoint, and logs the user in. If the account does not exist and `$wgOAuthLoginAutoCreate` is true, a local account is created using the profile data.

## User creation rules
- Username is taken from `preferred_username`, otherwise the local part of `email`, otherwise a sanitized `sub` claim.
- If `$wgOAuthLoginAllowedDomains` is non-empty, the user must have an email whose domain is on the list.
- Email is marked as confirmed when supplied by the provider.

## Notes and limitations
- The HTTP calls use MediaWiki's `HttpRequestFactory`; ensure outbound HTTPS is allowed from the server.
- Providers that require non-standard parameters may need code adjustments (PKCE, extra headers, etc.).
- The extension does not bundle a client library; it talks directly to the OAuth endpoints using JSON.

## Testing
- Use a test client on your provider with `Special:OAuthLogin` as the redirect URI.
- Verify login succeeds, a local account is created (if allowed), and the session persists across page loads.
- Try an email from a blocked domain (if configured) to confirm access is denied.
