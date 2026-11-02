<?php

namespace MediaWiki\Extension\OAuthLogin;

use MediaWiki\Config\Config;
use MediaWiki\Http\HttpRequestFactory;

use RuntimeException;

class OAuthClient {
	private Config $config;
	private HttpRequestFactory $httpFactory;

	public function __construct( Config $config, HttpRequestFactory $httpFactory ) {
		$this->config = $config;
		$this->httpFactory = $httpFactory;
	}

	/**
	 * Generate a PKCE code verifier (RFC 7636, 43-128 unreserved characters).
	 */
	public static function generateCodeVerifier(): string {
		return self::base64UrlEncode( random_bytes( 48 ) );
	}

	public static function generateState(): string {
		return bin2hex( random_bytes( 16 ) );
	}

	public static function base64UrlEncode( string $raw ): string {
		return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
	}

	public function getAuthorizationUrl( string $state, string $codeVerifier ): string {
		$query = [
			'response_type' => 'code',
			'client_id' => $this->config->get( 'OAuthLoginClientID' ),
			'redirect_uri' => $this->config->get( 'OAuthLoginRedirectURI' ),
			'scope' => $this->config->get( 'OAuthLoginScope' ),
			'state' => $state,
			'code_challenge' => self::base64UrlEncode( hash( 'sha256', $codeVerifier, true ) ),
			'code_challenge_method' => 'S256',
		];

		return wfAppendQuery( $this->config->get( 'OAuthLoginAuthURL' ), $query );
	}

	public function exchangeCodeForToken( string $code, string $codeVerifier ): array {
		$params = [
			'grant_type' => 'authorization_code',
			'code' => $code,
			'redirect_uri' => $this->config->get( 'OAuthLoginRedirectURI' ),
			'client_id' => $this->config->get( 'OAuthLoginClientID' ),
			'client_secret' => $this->config->get( 'OAuthLoginClientSecret' ),
			'code_verifier' => $codeVerifier,
		];

		$body = $this->doRequest( 'POST', $this->config->get( 'OAuthLoginTokenURL' ), $params, [
			'Accept' => 'application/json',
		] );

		$data = json_decode( $body, true );
		if ( !is_array( $data ) || empty( $data['access_token'] ) || !is_string( $data['access_token'] ) ) {
			throw new RuntimeException( 'token_response_missing_access_token' );
		}

		return $data;
	}

	public function fetchUserInfo( string $accessToken ): array {
		$body = $this->doRequest( 'GET', $this->config->get( 'OAuthLoginUserInfoURL' ), [], [
			'Accept' => 'application/json',
			'Authorization' => 'Bearer ' . $accessToken,
		] );

		$data = json_decode( $body, true );
		if ( !is_array( $data ) ) {
			throw new RuntimeException( 'userinfo_response_not_json' );
		}

		return $data;
	}

	private function doRequest( string $method, string $url, array $params, array $headers ): string {
		$options = [
			'method' => $method,
			'timeout' => 15,
			'followRedirects' => false,
		];

		if ( $method === 'POST' ) {
			$options['postData'] = $params;
		} elseif ( $params ) {
			$url = wfAppendQuery( $url, $params );
		}

		$request = $this->httpFactory->create( $url, $options, __METHOD__ );
		foreach ( $headers as $name => $value ) {
			$request->setHeader( $name, $value );
		}

		$status = $request->execute();
		if ( !$status->isOK() ) {
			throw new RuntimeException( 'http_error_' . ( $request->getStatus() ?: 'network' ) );
		}

		return $request->getContent();
	}
}
