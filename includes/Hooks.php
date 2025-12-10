<?php

namespace MediaWiki\Extension\OAuthLogin;

use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Title\Title;

class Hooks {
    public static function onPersonalUrls( array &$personalUrls, Title $title, $skin ): bool {
        $user = $skin->getUser();
        if ( $user->isRegistered() ) {
            return true;
        }

        $config = $skin->getConfig();
        if ( !$config->get( 'OAuthLoginAuthURL' ) || !$config->get( 'OAuthLoginClientID' ) ) {
            return true;
        }

        $loginTitle = SpecialPage::getTitleFor( 'OAuthLogin' );
        $personalUrls = [
            'oauthlogin' => [
                'text' => wfMessage( 'oauthlogin-login-link' )->text(),
                'href' => $loginTitle->getLocalURL(),
                'active' => $title->equals( $loginTitle ),
            ],
        ] + $personalUrls;

        $skin->getOutput()->addModules( [ 'ext.OAuthLogin.button' ] );

        return true;
    }
}
