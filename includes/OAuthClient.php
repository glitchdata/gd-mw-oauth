<?php

namespace MediaWiki\Extension\OAuthLogin;

use FormatJson;
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

    public function getAuthorizationUrl( string $state ): string {
        $query = [
            'response_type' => 'code',
            'client_id' => $this->config->get( 'OAuthLoginClientID' ),
            'redirect_uri' => $this->config->get( 'OAuthLoginRedirectURI' ),
            'scope' => $this->config->get( 'OAuthLoginScope' ),
            'state' => $state,
        ];

        return wfAppendQuery( $this->config->get( 'OAuthLoginAuthURL' ), $query );
    }

    public function exchangeCodeForToken( string $code ): array {
        $params = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config->get( 'OAuthLoginRedirectURI' ),
            'client_id' => $this->config->get( 'OAuthLoginClientID' ),
            'client_secret' => $this->config->get( 'OAuthLoginClientSecret' ),
        ];

        $body = $this->doRequest( 'POST', $this->config->get( 'OAuthLoginTokenURL' ), $params, [
            'Accept' => 'application/json',
        ] );

        $data = FormatJson::decode( $body, true );
        if ( !is_array( $data ) || !isset( $data['access_token'] ) ) {
            throw new RuntimeException( 'token_response_missing_access_token' );
        }

        return $data;
    }

    public function fetchUserInfo( string $accessToken ): array {
        $body = $this->doRequest( 'GET', $this->config->get( 'OAuthLoginUserInfoURL' ), [], [
            'Accept' => 'application/json',
            'Authorization' => 'Bearer ' . $accessToken,
        ] );

        $data = FormatJson::decode( $body, true );
        if ( !is_array( $data ) ) {
            throw new RuntimeException( 'userinfo_response_not_json' );
        }

        return $data;
    }

    private function doRequest( string $method, string $url, array $params, array $headers ): string {
        $options = [
            'method' => $method,
            'timeout' => 15,
            'headers' => $headers,
        ];

        if ( $method === 'POST' ) {
            $options['postData'] = $params;
        } elseif ( !empty( $params ) ) {
            $url = wfAppendQuery( $url, $params );
        }

        $request = $this->httpFactory->create( $url, $options );
        $status = $request->execute();

        if ( !$status->isOK() ) {
            throw new RuntimeException( 'http_error_' . $status->getValue() );
        }

        return $request->getContent();
    }
}
