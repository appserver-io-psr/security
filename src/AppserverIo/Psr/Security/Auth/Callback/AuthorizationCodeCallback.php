<?php

/**
 * AppserverIo\Psr\Security\Auth\Callback\AuthorizationCodeCallback
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
 * @copyright 2021 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/security
 * @link      http://www.appserver.io
 */

namespace AppserverIo\Psr\Security\Auth\Callback;

use AppserverIo\Lang\String;

/**
 * A callback implementation for the authorization code.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2021 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/security
 * @link      http://www.appserver.io
 */
class AuthorizationCodeCallback implements CallbackInterface
{

    /**
     * The authorization code.
     *
     * @var \AppserverIo\Lang\String
     */
    protected $authorizationCode;

    /**
     * Set's the passed authorization code.
     *
     * @param \AppserverIo\Lang\String $authorizationCode The authorization code to set
     *
     * @return void
     */
    public function setAuthorizationCode(String $authorizationCode)
    {
        $this->authorizationCode = $authorizationCode;
    }

    /**
     * Return's the authorization code.
     *
     * @return \AppserverIo\Lang\String The authorization code
     */
    public function getAuthorizationCode()
    {
        return $this->authorizationCode;
    }
}
