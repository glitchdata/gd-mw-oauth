<?php

namespace MediaWiki\Extension\OAuthLogin;

use MediaWiki\Hook\SkinTemplateNavigation__UniversalHook;
use MediaWiki\SpecialPage\SpecialPage;
use SkinTemplate;

class Hooks implements SkinTemplateNavigation__UniversalHook {
	/**
	 * Add a "Log in with OAuth" entry to the personal tools for anonymous users.
	 *
	 * @param SkinTemplate $sktemplate
	 * @param array &$links
	 */
	public function onSkinTemplateNavigation__Universal( $sktemplate, &$links ): void {
		if ( $sktemplate->getUser()->isRegistered() ) {
			return;
		}

		$config = $sktemplate->getConfig();
		if ( !$config->get( 'OAuthLoginAuthURL' ) || !$config->get( 'OAuthLoginClientID' ) ) {
			return;
		}

		$loginTitle = SpecialPage::getTitleFor( 'OAuthLogin' );
		$title = $sktemplate->getTitle();
		$query = [];
		if ( $title && !$title->isSpecial( 'Userlogin' ) && !$title->isSpecial( 'OAuthLogin' ) ) {
			$query['returnto'] = $title->getPrefixedText();
		}

		$entry = [
			'text' => $sktemplate->msg( 'oauthlogin-login-link' )->text(),
			'href' => $loginTitle->getLocalURL( $query ),
			'active' => $title && $title->equals( $loginTitle ),
			'icon' => 'logIn',
		];

		$links['user-menu'] = [ 'oauthlogin' => $entry ] + ( $links['user-menu'] ?? [] );

		$sktemplate->getOutput()->addModuleStyles( [ 'ext.OAuthLogin.button' ] );
	}
}
