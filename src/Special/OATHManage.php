<?php

/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 */

namespace MediaWiki\Extension\OATHAuth\Special;

use ErrorPageError;
use MediaWiki\Config\ConfigException;
use MediaWiki\Exception\MWException;
use MediaWiki\Exception\PermissionsError;
use MediaWiki\Exception\UserNotLoggedIn;
use MediaWiki\Extension\OATHAuth\HTMLForm\IManageForm;
use MediaWiki\Extension\OATHAuth\IAuthKey;
use MediaWiki\Extension\OATHAuth\IModule;
use MediaWiki\Extension\OATHAuth\OATHAuthModuleRegistry;
use MediaWiki\Extension\OATHAuth\OATHUser;
use MediaWiki\Extension\OATHAuth\OATHUserRepository;
use MediaWiki\Html\Html;
use MediaWiki\HTMLForm\HTMLForm;
use MediaWiki\Message\Message;
use MediaWiki\SpecialPage\SpecialPage;
use OOUI\ButtonWidget;
use OOUI\HorizontalLayout;
use OOUI\HtmlSnippet;
use OOUI\LabelWidget;
use OOUI\PanelLayout;

class OATHManage extends SpecialPage {
	public const ACTION_ENABLE = 'enable';
	public const ACTION_DISABLE = 'disable';

	protected OATHAuthModuleRegistry $moduleRegistry;

	protected OATHUserRepository $userRepo;

	protected OATHUser $authUser;

	/**
	 * @var string
	 */
	protected $action;

	protected ?IModule $requestedModule;

	/**
	 * Initializes a page to manage available 2FA modules
	 *
	 * @param OATHUserRepository $userRepo
	 * @param OATHAuthModuleRegistry $moduleRegistry
	 *
	 * @throws ConfigException
	 * @throws MWException
	 */
	public function __construct( OATHUserRepository $userRepo, OATHAuthModuleRegistry $moduleRegistry ) {
		// messages used: oathmanage (display "name" on Special:SpecialPages),
		// right-oathauth-enable, action-oathauth-enable
		parent::__construct( 'OATHManage', 'oathauth-enable' );

		$this->userRepo = $userRepo;
		$this->moduleRegistry = $moduleRegistry;
	}

	/**
	 * @inheritDoc
	 */
	protected function getGroupName() {
		return 'login';
	}

	/**
	 * @param null|string $subPage
	 */
	public function execute( $subPage ) {
		$this->authUser = $this->userRepo->findByUser( $this->getUser() );

		$this->getOutput()->enableOOUI();
		$this->getOutput()->disallowUserJs();
		$this->setAction();
		$this->setModule();

		parent::execute( $subPage );

		if ( $this->requestedModule instanceof IModule ) {
			// Performing an action on a requested module
			$this->clearPage();
			if ( $this->shouldShowDisableWarning() ) {
				$this->showDisableWarning( $this->requestedModule );
				return;
			}
			$this->addModuleHTML( $this->requestedModule );
			return;
		}

		$this->addGeneralHelp();
		if ( $this->authUser->isTwoFactorAuthEnabled() ) {
			$this->addEnabledHTML();
			if ( $this->hasAlternativeModules() ) {
				$this->addAlternativesHTML();
			}
			return;
		}
		$this->nothingEnabled();
	}

	/**
	 * @throws PermissionsError
	 * @throws UserNotLoggedIn
	 */
	public function checkPermissions() {
		$this->requireNamedUser();

		if ( !$this->authUser->getCentralId() ) {
			throw new ErrorPageError(
				'oathauth-enable',
				'oathauth-must-be-central',
				[ $this->getUser()->getName() ]
			);
		}

		$canEnable = $this->getUser()->isAllowed( 'oathauth-enable' );

		if ( $this->action === static::ACTION_ENABLE && !$canEnable ) {
			$this->displayRestrictionError();
		}

		if ( !$this->authUser->isTwoFactorAuthEnabled() && !$canEnable ) {
			// No enabled module and cannot enable - nothing to do
			$this->displayRestrictionError();
		}

		if ( $this->action === static::ACTION_ENABLE && !$this->getRequest()->wasPosted() ) {
			// Trying to change the 2FA method (one is already enabled)
			$this->checkLoginSecurityLevel( 'oathauth-enable' );
		}
	}

	private function setAction(): void {
		$this->action = $this->getRequest()->getVal( 'action', '' );
	}

	private function setModule(): void {
		$moduleKey = $this->getRequest()->getVal( 'module', '' );
		$this->requestedModule = ( $moduleKey && $this->moduleRegistry->moduleExists( $moduleKey ) )
			? $this->moduleRegistry->getModuleByKey( $moduleKey )
			: null;
	}

	private function addEnabledHTML(): void {
		$this->addHeading( $this->msg( 'oathauth-ui-enabled-module' ) );

		$modules = array_unique(
			array_map(
				static fn ( IAuthKey $key ) => $key->getModule(),
				$this->authUser->getKeys(),
			)
		);

		foreach ( $modules as $module ) {
			$this->addModuleHTML( $this->moduleRegistry->getModuleByKey( $module ) );
		}
	}

	private function addAlternativesHTML(): void {
		$this->addHeading( $this->msg( 'oathauth-ui-not-enabled-modules' ) );
		$this->addInactiveHTML();
	}

	private function nothingEnabled(): void {
		$this->addHeading( $this->msg( 'oathauth-ui-available-modules' ) );
		$this->addInactiveHTML();
	}

	private function addInactiveHTML(): void {
		foreach ( $this->moduleRegistry->getAllModules() as $module ) {
			if ( $this->isModuleEnabled( $module ) || !$this->isModuleAvailable( $module ) ) {
				continue;
			}
			$this->addModuleHTML( $module );
		}
	}

	private function addGeneralHelp(): void {
		$this->getOutput()->addHTML( $this->msg(
			'oathauth-ui-general-help'
		)->parseAsBlock() );
	}

	private function addModuleHTML( IModule $module ): void {
		if ( $this->isModuleRequested( $module ) ) {
			$this->addCustomContent( $module );
			return;
		}

		$panel = $this->getGenericContent( $module );
		if ( $this->isModuleEnabled( $module ) ) {
			$this->addCustomContent( $module, $panel );
		}

		$this->getOutput()->addHTML( (string)$panel );
	}

	/**
	 * Get the panel with generic content for a module
	 */
	private function getGenericContent( IModule $module ): PanelLayout {
		$modulePanel = new PanelLayout( [
			'framed' => true,
			'expanded' => false,
			'padded' => true
		] );
		$headerLayout = new HorizontalLayout();

		$label = new LabelWidget( [
			'label' => $module->getDisplayName()->text()
		] );
		if ( $this->shouldShowGenericButtons() ) {
			$enabled = $this->isModuleEnabled( $module );
			$urlParams = [
				'action' => $enabled ? static::ACTION_DISABLE : static::ACTION_ENABLE,
				'module' => $module->getName(),
			];
			if ( $enabled ) {
				$urlParams['warn'] = 1;
			}
			$button = new ButtonWidget( [
				'label' => $this
					->msg( $enabled ? 'oathauth-disable-generic' : 'oathauth-enable-generic' )
					->text(),
				'href' => $this->getOutput()->getTitle()->getLocalURL( $urlParams )
			] );
			$headerLayout->addItems( [ $button ] );
		}
		$headerLayout->addItems( [ $label ] );

		$modulePanel->appendContent( $headerLayout );
		$modulePanel->appendContent( new HtmlSnippet(
			$module->getDescriptionMessage()->parseAsBlock()
		) );
		return $modulePanel;
	}

	private function addCustomContent( IModule $module, ?PanelLayout $panel = null ): void {
		$form = $module->getManageForm(
			$this->action,
			$this->authUser,
			$this->userRepo,
			$this->getContext()
		);
		if ( $form === null || !$this->isValidFormType( $form ) ) {
			return;
		}
		$form->setTitle( $this->getOutput()->getTitle() );
		$this->ensureRequiredFormFields( $form, $module );
		$form->setSubmitCallback( [ $form, 'onSubmit' ] );
		if ( $form->show( $panel ) ) {
			$form->onSuccess();
		}
	}

	private function addHeading( Message $message ): void {
		$this->getOutput()->addHTML( Html::element( 'h2', [], $message->text() ) );
	}

	private function shouldShowGenericButtons(): bool {
		return !$this->requestedModule instanceof IModule || !$this->isGenericAction();
	}

	private function isModuleRequested( ?IModule $module ): bool {
		return (
			$this->requestedModule instanceof IModule
			&& $module instanceof IModule
			&& $this->requestedModule->getName() === $module->getName()
		);
	}

	private function isModuleEnabled( IModule $module ): bool {
		return (bool)$this->authUser->getKeysForModule( $module->getName() );
	}

	/**
	 * Verifies if the module is available to be enabled
	 *
	 * @param IModule $module
	 * @return bool
	 */
	private function isModuleAvailable( IModule $module ): bool {
		$form = $module->getManageForm(
			static::ACTION_ENABLE,
			$this->authUser,
			$this->userRepo,
			$this->getContext()
		);
		if ( $form === '' ) {
			return false;
		}
		return true;
	}

	/**
	 * Verifies if the given form instance fulfills the required conditions
	 *
	 * @param mixed $form
	 * @return bool
	 */
	private function isValidFormType( $form ): bool {
		if ( !( $form instanceof HTMLForm ) ) {
			return false;
		}
		$implements = class_implements( $form );
		if ( !isset( $implements[IManageForm::class] ) ) {
			return false;
		}

		return true;
	}

	private function ensureRequiredFormFields( IManageForm $form, IModule $module ): void {
		if ( !$form->hasField( 'module' ) ) {
			$form->addHiddenField( 'module', $module->getName() );
		}
		if ( !$form->hasField( 'action' ) ) {
			$form->addHiddenField( 'action', $this->action );
		}
	}

	/**
	 * When performing an action on a module (like enable/disable),
	 * page should contain only the form for that action.
	 */
	private function clearPage(): void {
		if ( $this->isGenericAction() ) {
			$displayName = $this->requestedModule->getDisplayName();
			$pageTitleMessage = $this->isModuleEnabled( $this->requestedModule ) ?
				$this->msg( 'oathauth-disable-page-title', $displayName ) :
				$this->msg( 'oathauth-enable-page-title', $displayName );
			$this->getOutput()->setPageTitleMsg( $pageTitleMessage );
		}

		$this->getOutput()->clearHTML();
		$this->getOutput()->addBacklinkSubtitle( $this->getOutput()->getTitle() );
	}

	/**
	 * The enable and disable actions are generic, and all modules must
	 * implement them, while all other actions are module-specific.
	 */
	private function isGenericAction(): bool {
		return in_array( $this->action, [ static::ACTION_ENABLE, static::ACTION_DISABLE ] );
	}

	private function hasAlternativeModules(): bool {
		foreach ( $this->moduleRegistry->getAllModules() as $module ) {
			if ( !$this->isModuleEnabled( $module ) && $this->isModuleAvailable( $module ) ) {
				return true;
			}
		}
		return false;
	}

	private function shouldShowDisableWarning(): bool {
		return $this->getRequest()->getBool( 'warn' ) &&
			$this->requestedModule instanceof IModule &&
			$this->action === static::ACTION_DISABLE &&
			$this->authUser->isTwoFactorAuthEnabled();
	}

	private function showDisableWarning( IModule $module ): void {
		$panel = new PanelLayout( [
			'padded' => true,
			'framed' => true,
			'expanded' => false
		] );

		$currentDisplayName = $module->getDisplayName();

		$panel->appendContent( new HtmlSnippet(
			$this->msg( 'oathauth-disable-method-warning', $currentDisplayName )->parseAsBlock()
		) );

		$customMessage = $module->getDisableWarningMessage();
		if ( $customMessage instanceof Message ) {
			$panel->appendContent( new HtmlSnippet(
				$customMessage->parseAsBlock()
			) );
		}

		$panel->appendContent( new HtmlSnippet(
			$this->msg( 'oathauth-disable-method-next-step', $currentDisplayName )->parseAsBlock()
		) );

		$button = new ButtonWidget( [
			'label' => $this->msg( 'oathauth-disable-method-warning-button-label' )->plain(),
			'href' => $this->getOutput()->getTitle()->getLocalURL( [
				'action' => $this->action,
				'module' => $this->requestedModule->getName()
			] ),
			'flags' => [ 'primary', 'progressive' ]
		] );
		$panel->appendContent( $button );

		$this->getOutput()->setPageTitleMsg( $this->msg( 'oathauth-disable-method-warning-header' ) );
		$this->getOutput()->addHTML( $panel->toString() );
	}

}
