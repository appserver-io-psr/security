<?php

/**
 * AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 *
 * PHP version 5
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/security
 * @link      http://www.appserver.io
 */

namespace AppserverIo\Psr\Security\Auth\Spi;

use AppserverIo\Collections\MapInterface;
use AppserverIo\Psr\Security\Auth\Subject;
use AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface;

/**
 * Interface for all login module implementations.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/security
 * @link      http://www.appserver.io
 */
interface LoginModuleInterface
{

    /**
     * Initialize the login module. This stores the subject, callbackHandler and sharedState and options
     * for the login session. Subclasses should override if they need to process their own options. A call
     * to parent::initialize() must be made in the case of an override.
     *
     * The following parameters can by default be passed from the configuration.
     *
     * password-stacking:       If this is set to "useFirstPass", the login identity will be taken from the
     *                          servlet_engine.authentication.login_module.login_name value of the sharedState map, and the proof of
     *                          identity from the servlet_engine.authentication.login_module.login_password value of the sharedState map
     * principalClass:          A Principal implementation that support a constructor taking a string argument for the princpal name
     * unauthenticatedIdentity: The name of the principal to asssign and authenticate when a null username and password are seen
     *
     * @param \AppserverIo\Psr\Security\Auth\Subject                           $subject         The Subject to update after a successful login
     * @param \AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface $callbackHandler The callback handler that will be used to obtain the user identity and credentials
     * @param \AppserverIo\Collections\MapInterface                            $sharedState     A map shared between all configured login module instances
     * @param \AppserverIo\Collections\MapInterface                            $params          The parameters passed to the login module
     *
     * @return void
     */
    public function initialize(Subject $subject, CallbackHandlerInterface $callbackHandler, MapInterface $sharedState, MapInterface $params);

    /**
     * Looks for servlet_engine.authentication.login_module.login_name and servlet_engine.authentication.login_module.login_password
     * values in the sharedState map if the useFirstPass option was true and returns TRUE if they exist. If they do not or are NULL
     * this method returns FALSE.
     *
     * Note that subclasses that override the login method must set the loginOk var to TRUE if the login succeeds in order for the
     * commit phase to populate the Subject. This implementation sets loginOk to TRUE if the login() method returns TRUE, otherwise,
     * it sets loginOk to FALSE. Perform the authentication of username and password.
     *
     * @return boolean TRUE if the login credentials are available in the sharedMap, else FALSE
     * @throws \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if an error during login occured
     */
    public function login();

    /**
     * Performs the user logout.
     *
     * @throws \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if an error during logout occured
     *
     * @return void
     */
    public function logout();

    /**
     * Abort the current login attempt.
     *
     * This is called after login() if the overall login attempt fails (that is, if one of the other login modules
     * that is REQUIRED or REQUISITE fails). This method should clean up this module's saved state, if any.
     *
     * @return void
     * @throws \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if the abort fails
     */
    public function abort();

    /**
     * Commit the current login attempt.
     *
     * This is called after login() if the overall login attempt succeeds (that is, all methods have satisfied all
     * REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL module requirements).
     *
     * @return void
     * @throws \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if the commit fails
     */
    public function commit();
}
