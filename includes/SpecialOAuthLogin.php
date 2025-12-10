<?php

namespace MediaWiki\Extension\OAuthLogin;

use MediaWiki\Config\Config;
use MediaWiki\MediaWikiServices;
use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\User\User;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentityLookup;
use MediaWiki\User\UserRigorOptions;
use MWCryptRand;
use RuntimeException;

class SpecialOAuthLogin extends SpecialPage {
    private Config $config;
    private OAuthClient $client;
    private UserFactory $userFactory;
    private UserIdentityLookup $identityLookup;

    public function __construct() {
        parent::__construct( 'OAuthLogin' );

        $services = MediaWikiServices::getInstance();
        $this->config = $services->getMainConfig();
        $this->client = new OAuthClient( $this->config, $services->getHttpRequestFactory() );
        $this->userFactory = $services->getUserFactory();
        $this->identityLookup = $services->getUserIdentityLookup();
    }

    public function execute( $subPage ) {
        $this->setHeaders();
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

        $state = $request->getVal( 'state' );
        $code = $request->getVal( 'code' );

        if ( $state && $code ) {
            $this->handleCallback( $state, $code );
            return;
        }

        $this->beginLogin();
    }

    private function isConfigured(): bool {
        return (bool)$this->config->get( 'OAuthLoginAuthURL' )
            && (bool)$this->config->get( 'OAuthLoginTokenURL' )
            && (bool)$this->config->get( 'OAuthLoginUserInfoURL' )
            && (bool)$this->config->get( 'OAuthLoginClientID' )
            && (bool)$this->config->get( 'OAuthLoginClientSecret' )
            && (bool)$this->config->get( 'OAuthLoginRedirectURI' );
    }

    private function beginLogin(): void {
        $session = $this->getRequest()->getSession();
        $state = MWCryptRand::generateHex( 16 );
        $session->set( 'oauthlogin-state', $state );

        $this->getOutput()->redirect( $this->client->getAuthorizationUrl( $state ) );
    }

    private function handleCallback( string $state, string $code ): void {
        $out = $this->getOutput();
        $session = $this->getRequest()->getSession();
        $expectedState = $session->get( 'oauthlogin-state' );

        if ( !$expectedState || $expectedState !== $state ) {
            $out->addWikiMsg( 'oauthlogin-error-state' );
            return;
        }

        try {
            $token = $this->client->exchangeCodeForToken( $code );
            $profile = $this->client->fetchUserInfo( $token['access_token'] );
            $user = $this->resolveUser( $profile );
            $this->logInUser( $user );

            $out->addWikiMsg( 'oauthlogin-success-title' );
            $out->addWikiMsg( 'oauthlogin-success-body', $user->getName() );
        } catch ( RuntimeException $ex ) {
            $out->addWikiMsg( $this->mapErrorToMessage( $ex->getMessage() ) );
        }
    }

    private function resolveUser( array $profile ): User {
        $email = $profile['email'] ?? null;
        $this->enforceAllowedDomains( $email );

        $username = $this->buildUsername( $profile );
        $existingIdentity = $this->identityLookup->getUserIdentityByName( $username );

        if ( $existingIdentity ) {
            return $this->userFactory->newFromUserIdentity( $existingIdentity );
        }

        if ( !$this->config->get( 'OAuthLoginAutoCreate' ) ) {
            throw new RuntimeException( 'autocreation_disabled' );
        }

        return $this->createUser( $username, $email, $profile );
    }

    private function enforceAllowedDomains( ?string $email ): void {
        $allowedDomains = $this->config->get( 'OAuthLoginAllowedDomains' );
        if ( !$allowedDomains ) {
            return;
        }

        if ( !$email ) {
            throw new RuntimeException( 'email_required_for_domain_check' );
        }

        $domain = strtolower( substr( strrchr( $email, '@' ) ?: '', 1 ) );
        if ( !$domain || !in_array( $domain, array_map( 'strtolower', $allowedDomains ), true ) ) {
            throw new RuntimeException( 'email_domain_not_allowed' );
        }
    }

    private function buildUsername( array $profile ): string {
        if ( !empty( $profile['preferred_username'] ) ) {
            $candidate = $profile['preferred_username'];
        } elseif ( !empty( $profile['email'] ) && strpos( $profile['email'], '@' ) !== false ) {
            $candidate = strstr( $profile['email'], '@', true );
        } elseif ( !empty( $profile['sub'] ) ) {
            $candidate = 'oauth-' . substr( preg_replace( '/[^A-Za-z0-9]/', '', $profile['sub'] ), 0, 12 );
        } else {
            throw new RuntimeException( 'missing_identifier' );
        }

        $candidate = preg_replace( '/[^A-Za-z0-9_.-]/', '_', $candidate );
        $candidate = trim( $candidate, ' _.-' );

        $user = $this->userFactory->newFromName( $candidate, UserRigorOptions::RIGOR_CREATABLE );
        if ( !$user ) {
            throw new RuntimeException( 'invalid_username' );
        }

        return $user->getName();
    }

    private function createUser( string $username, ?string $email, array $profile ): User {
        $user = $this->userFactory->newFromName( $username, UserRigorOptions::RIGOR_CREATABLE );
        if ( !$user ) {
            throw new RuntimeException( 'invalid_username' );
        }

        $user->addToDatabase();

        if ( $email ) {
            $user->setEmail( $email );
            $user->confirmEmail();
        }

        if ( !empty( $profile['name'] ) ) {
            $user->setRealName( $profile['name'] );
        }

        $user->setToken();
        $user->saveSettings();

        return $user;
    }

    private function logInUser( User $user ): void {
        $context = $this->getContext();
        $request = $context->getRequest();
        $response = $request->response();

        $context->setUser( $user );
        $request->getSession()->setUser( $user );
        $user->setCookies( $request, $response, true );
    }

    private function mapErrorToMessage( string $code ): string {
        $map = [
            'token_response_missing_access_token' => 'oauthlogin-error-token',
            'userinfo_response_not_json' => 'oauthlogin-error-userinfo',
            'email_domain_not_allowed' => 'oauthlogin-error-domain',
            'email_required_for_domain_check' => 'oauthlogin-error-domain',
        ];

        foreach ( $map as $needle => $message ) {
            if ( strpos( $code, $needle ) !== false ) {
                return $message;
            }
        }

        return 'oauthlogin-error-generic';
    }
}
