<?php

namespace MediaWiki\Extension\OAuthLogin;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Config\Config;
use MediaWiki\HookContainer\HookContainer;
use MediaWiki\Http\HttpRequestFactory;
use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Title\Title;
use MediaWiki\User\UserOptionsManager;
use MediaWiki\User\User;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentityLookup;
use MediaWiki\User\UserRigorOptions;
use RuntimeException;
use Wikimedia\Rdbms\IConnectionProvider;

class SpecialOAuthLogin extends SpecialPage {
	/** User option that stores the provider's stable subject identifier. */
	public const OPTION_SUB = 'oauthlogin-sub';

	/** Session keys. */
	private const SESSION_STATE = 'oauthlogin-state';
	private const SESSION_VERIFIER = 'oauthlogin-verifier';
	private const SESSION_STARTED = 'oauthlogin-started';
	private const SESSION_RETURNTO = 'oauthlogin-returnto';

	/** Maximum age of an authorization request before the state is rejected. */
	private const STATE_TTL = 600;

	private Config $config;
	private OAuthClient $client;
	private UserFactory $userFactory;
	private UserIdentityLookup $identityLookup;
	private UserOptionsManager $userOptionsManager;
	private AuthManager $authManager;
	private HookContainer $hookContainer;
	private IConnectionProvider $dbProvider;

	public function __construct(
		Config $config,
		HttpRequestFactory $httpRequestFactory,
		UserFactory $userFactory,
		UserIdentityLookup $identityLookup,
		UserOptionsManager $userOptionsManager,
		AuthManager $authManager,
		HookContainer $hookContainer,
		IConnectionProvider $dbProvider
	) {
		parent::__construct( 'OAuthLogin' );
		$this->config = $config;
		$this->client = new OAuthClient( $config, $httpRequestFactory );
		$this->userFactory = $userFactory;
		$this->identityLookup = $identityLookup;
		$this->userOptionsManager = $userOptionsManager;
		$this->authManager = $authManager;
		$this->hookContainer = $hookContainer;
		$this->dbProvider = $dbProvider;
	}

	public function doesWrites(): bool {
		return true;
	}

	protected function getGroupName(): string {
		return 'login';
	}

	public function execute( $subPage ) {
		$this->setHeaders();
		$this->outputHeader();
		$out = $this->getOutput();
		$request = $this->getRequest();

		if ( !$this->isConfigured() ) {
			$out->addWikiMsg( 'oauthlogin-missing-config' );
			return;
		}

		if ( $this->getUser()->isRegistered() ) {
			$out->addWikiMsg( 'oauthlogin-already-logged-in' );
			return;
		}

		$session = $request->getSession();

		// Provider reported an error (e.g. the user cancelled).
		$error = $request->getVal( 'error' );
		if ( $error !== null ) {
			$this->clearSessionState();
			$out->addWikiMsg( $error === 'access_denied' ? 'oauthlogin-error-denied' : 'oauthlogin-error-provider' );
			$out->addWikiMsg( 'oauthlogin-retry', $this->getPageTitle()->getPrefixedText() );
			return;
		}

		$state = $request->getVal( 'state' );
		$code = $request->getVal( 'code' );

		if ( $state !== null && $code !== null ) {
			$this->handleCallback( $state, $code );
			return;
		}

		$returnTo = $request->getVal( 'returnto' );
		if ( $returnTo !== null ) {
			$session->set( self::SESSION_RETURNTO, $returnTo );
		}
		$this->beginLogin();
	}

	private function isConfigured(): bool {
		foreach ( [
			'OAuthLoginAuthURL', 'OAuthLoginTokenURL', 'OAuthLoginUserInfoURL',
			'OAuthLoginClientID', 'OAuthLoginClientSecret', 'OAuthLoginRedirectURI',
		] as $key ) {
			if ( !$this->config->get( $key ) ) {
				return false;
			}
		}
		return true;
	}

	private function beginLogin(): void {
		$session = $this->getRequest()->getSession();
		$session->persist();

		$state = OAuthClient::generateState();
		$verifier = OAuthClient::generateCodeVerifier();

		$session->set( self::SESSION_STATE, $state );
		$session->set( self::SESSION_VERIFIER, $verifier );
		$session->set( self::SESSION_STARTED, time() );
		$session->save();

		$this->getOutput()->redirect( $this->client->getAuthorizationUrl( $state, $verifier ) );
	}

	private function clearSessionState(): void {
		$session = $this->getRequest()->getSession();
		foreach ( [ self::SESSION_STATE, self::SESSION_VERIFIER, self::SESSION_STARTED ] as $key ) {
			$session->remove( $key );
		}
	}

	private function handleCallback( string $state, string $code ): void {
		$out = $this->getOutput();
		$session = $this->getRequest()->getSession();

		$expectedState = $session->get( self::SESSION_STATE );
		$verifier = $session->get( self::SESSION_VERIFIER );
		$started = (int)$session->get( self::SESSION_STARTED, 0 );

		// Single use: whatever happens next, this state cannot be replayed.
		$this->clearSessionState();

		if ( !is_string( $expectedState ) || !is_string( $verifier )
			|| !hash_equals( $expectedState, $state )
			|| $started <= 0 || ( time() - $started ) > self::STATE_TTL
		) {
			$out->addWikiMsg( 'oauthlogin-error-state' );
			$out->addWikiMsg( 'oauthlogin-retry', $this->getPageTitle()->getPrefixedText() );
			return;
		}

		try {
			$token = $this->client->exchangeCodeForToken( $code, $verifier );
			$profile = $this->client->fetchUserInfo( $token['access_token'] );
			$user = $this->resolveUser( $profile );
			$this->logInUser( $user );
		} catch ( RuntimeException $ex ) {
			wfDebugLog( 'OAuthLogin', 'Login failed: ' . $ex->getMessage() );
			$out->addWikiMsg( $this->mapErrorToMessage( $ex->getMessage() ) );
			$out->addWikiMsg( 'oauthlogin-retry', $this->getPageTitle()->getPrefixedText() );
			return;
		}

		$returnTo = $session->get( self::SESSION_RETURNTO );
		$session->remove( self::SESSION_RETURNTO );
		$target = is_string( $returnTo ) ? Title::newFromText( $returnTo ) : null;
		if ( !$target || $target->isExternal() || $target->isSpecial( 'Userlogout' ) ) {
			$target = Title::newMainPage();
		}
		$out->redirect( $target->getFullURL() );
	}

	/**
	 * Map a provider profile to a local user.
	 *
	 * Order of resolution:
	 *  1. A local account already bound to this provider subject.
	 *  2. Optionally, an existing account whose confirmed email matches a verified
	 *     provider email ($wgOAuthLoginLinkByEmail).
	 *  3. A new auto-created account with a free username.
	 *
	 * Existing accounts are never logged into merely because a username matches.
	 */
	private function resolveUser( array $profile ): User {
		$sub = $profile['sub'] ?? null;
		if ( !is_string( $sub ) || $sub === '' ) {
			throw new RuntimeException( 'missing_identifier' );
		}

		$email = $this->extractEmail( $profile );
		$emailVerified = $email !== null && ( $profile['email_verified'] ?? false ) === true;

		$this->enforceAllowedDomains( $email, $emailVerified );

		$user = $this->findUserBySubject( $sub );
		if ( $user ) {
			return $user;
		}

		if ( $email && $emailVerified && $this->config->get( 'OAuthLoginLinkByEmail' ) ) {
			$user = $this->findUserByConfirmedEmail( $email );
			if ( $user ) {
				$this->bindSubject( $user, $sub );
				return $user;
			}
		}

		if ( !$this->config->get( 'OAuthLoginAutoCreate' ) ) {
			throw new RuntimeException( 'autocreation_disabled' );
		}

		return $this->createUser( $this->buildUsername( $profile ), $sub, $email, $emailVerified, $profile );
	}

	private function extractEmail( array $profile ): ?string {
		$email = $profile['email'] ?? null;
		if ( !is_string( $email ) || $email === '' ) {
			return null;
		}
		$email = trim( $email );
		if ( !filter_var( $email, FILTER_VALIDATE_EMAIL ) || substr_count( $email, '@' ) !== 1 ) {
			throw new RuntimeException( 'invalid_email' );
		}
		return $email;
	}

	private function enforceAllowedDomains( ?string $email, bool $emailVerified ): void {
		$allowedDomains = $this->config->get( 'OAuthLoginAllowedDomains' );
		if ( !$allowedDomains ) {
			return;
		}

		if ( !$email || !$emailVerified ) {
			throw new RuntimeException( 'email_required_for_domain_check' );
		}

		$domain = strtolower( substr( $email, strrpos( $email, '@' ) + 1 ) );
		if ( $domain === '' || !in_array( $domain, array_map( 'strtolower', $allowedDomains ), true ) ) {
			throw new RuntimeException( 'email_domain_not_allowed' );
		}
	}

	private function findUserBySubject( string $sub ): ?User {
		$userId = $this->dbProvider->getReplicaDatabase()->newSelectQueryBuilder()
			->select( 'up_user' )
			->from( 'user_properties' )
			->where( [ 'up_property' => self::OPTION_SUB, 'up_value' => $sub ] )
			->caller( __METHOD__ )
			->fetchField();

		if ( !$userId ) {
			return null;
		}

		$user = $this->userFactory->newFromId( (int)$userId );
		$user->load();
		if ( !$user->isRegistered() ) {
			return null;
		}
		// Defend against a stale replica or a tampered row: the option must round-trip.
		if ( $this->userOptionsManager->getOption( $user, self::OPTION_SUB ) !== $sub ) {
			return null;
		}
		return $user;
	}

	private function findUserByConfirmedEmail( string $email ): ?User {
		$dbr = $this->dbProvider->getReplicaDatabase();
		$ids = $dbr->newSelectQueryBuilder()
			->select( 'user_id' )
			->from( 'user' )
			->where( [
				'user_email' => $email,
				'user_email_authenticated IS NOT NULL',
			] )
			->limit( 2 )
			->caller( __METHOD__ )
			->fetchFieldValues();

		// Refuse to guess if the email is shared by more than one account.
		if ( count( $ids ) !== 1 ) {
			return null;
		}

		$user = $this->userFactory->newFromId( (int)$ids[0] );
		$user->load();
		// Never silently attach to an account that is already bound to another subject.
		if ( !$user->isRegistered() || $this->userOptionsManager->getOption( $user, self::OPTION_SUB ) ) {
			return null;
		}
		return $user;
	}

	private function bindSubject( User $user, string $sub ): void {
		$this->userOptionsManager->setOption( $user, self::OPTION_SUB, $sub );
		$this->userOptionsManager->saveOptions( $user );
	}

	/**
	 * Build a free, creatable username from the profile. Never returns the name
	 * of an existing account.
	 */
	private function buildUsername( array $profile ): string {
		if ( !empty( $profile['preferred_username'] ) && is_string( $profile['preferred_username'] ) ) {
			$candidate = $profile['preferred_username'];
		} elseif ( !empty( $profile['email'] ) && is_string( $profile['email'] ) && strpos( $profile['email'], '@' ) !== false ) {
			$candidate = strstr( $profile['email'], '@', true );
		} else {
			$candidate = 'oauth-' . substr( preg_replace( '/[^A-Za-z0-9]/', '', (string)$profile['sub'] ), 0, 12 );
		}

		$candidate = preg_replace( '/[^A-Za-z0-9_.\- ]/', '_', $candidate );
		$candidate = trim( $candidate, ' _.-' );
		if ( $candidate === '' ) {
			$candidate = 'oauth-' . substr( preg_replace( '/[^A-Za-z0-9]/', '', (string)$profile['sub'] ), 0, 12 );
		}

		$base = $this->userFactory->newFromName( $candidate, UserRigorOptions::RIGOR_CREATABLE );
		if ( !$base ) {
			throw new RuntimeException( 'invalid_username' );
		}
		$baseName = $base->getName();

		for ( $i = 0; $i < 100; $i++ ) {
			$name = $i === 0 ? $baseName : $baseName . ( $i + 1 );
			$user = $this->userFactory->newFromName( $name, UserRigorOptions::RIGOR_CREATABLE );
			if ( !$user ) {
				continue;
			}
			if ( !$this->identityLookup->getUserIdentityByName( $user->getName() )
				&& $this->authManager->canCreateAccount( $user->getName() )->isOK()
			) {
				return $user->getName();
			}
		}

		throw new RuntimeException( 'invalid_username' );
	}

	private function createUser( string $username, string $sub, ?string $email, bool $emailVerified, array $profile ): User {
		$user = $this->userFactory->newFromName( $username, UserRigorOptions::RIGOR_CREATABLE );
		if ( !$user ) {
			throw new RuntimeException( 'invalid_username' );
		}

		// Goes through AuthManager so IP blocks, creation permissions, the new user
		// log and LocalUserCreated hooks all apply.
		$status = $this->authManager->autoCreateUser( $user, AuthManager::AUTOCREATE_SOURCE_SESSION, false );
		if ( !$status->isOK() ) {
			wfDebugLog( 'OAuthLogin', 'autoCreateUser failed: ' . $status->getWikiText( false, false, 'en' ) );
			throw new RuntimeException( 'autocreate_failed' );
		}

		$user->load( \IDBAccessObject::READ_LATEST );

		if ( $email ) {
			$user->setEmail( $email );
			if ( $emailVerified ) {
				$user->confirmEmail();
			}
		}
		if ( !empty( $profile['name'] ) && is_string( $profile['name'] ) ) {
			$user->setRealName( $profile['name'] );
		}
		$user->saveSettings();

		$this->bindSubject( $user, $sub );

		return $user;
	}

	private function logInUser( User $user ): void {
		if ( $user->getBlock() && $user->getBlock()->isSitewide() && $user->getBlock()->appliesToRight( 'read' ) ) {
			throw new RuntimeException( 'user_blocked' );
		}

		$request = $this->getRequest();
		$session = $request->getSession();

		$delay = $session->delaySave();
		$session->resetId();
		$session->resetAllTokens();
		$session->setUser( $user );
		$session->setRememberUser( (bool)$this->config->get( 'OAuthLoginRememberMe' ) );
		$session->persist();
		\Wikimedia\ScopedCallback::consume( $delay );

		$user->touch();
		$this->getContext()->setUser( $user );

		$this->hookContainer->run( 'UserLoggedIn', [ $user ] );
	}

	private function mapErrorToMessage( string $code ): string {
		$map = [
			'token_response_missing_access_token' => 'oauthlogin-error-token',
			'userinfo_response_not_json' => 'oauthlogin-error-userinfo',
			'email_domain_not_allowed' => 'oauthlogin-error-domain',
			'email_required_for_domain_check' => 'oauthlogin-error-domain',
			'autocreation_disabled' => 'oauthlogin-error-noaccount',
			'autocreate_failed' => 'oauthlogin-error-noaccount',
			'user_blocked' => 'oauthlogin-error-blocked',
		];

		foreach ( $map as $needle => $message ) {
			if ( strpos( $code, $needle ) !== false ) {
				return $message;
			}
		}

		return 'oauthlogin-error-generic';
	}
}
