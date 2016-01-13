<?php

/**
 * AppserverIo\Psr\Security\Auth\Callback\PasswordCallback
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

namespace AppserverIo\Psr\Security\Auth\Callback;

use AppserverIo\Lang\String;

/**
 * A password callback implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/security
 * @link      http://www.appserver.io
 */
class PasswordCallback implements CallbackInterface
{

    /**
     * The user's password.
     *
     * @var \AppserverIo\Lang\String
     */
    protected $password;

    /**
     * Set's the passed password.
     *
     * @param \AppserverIo\Lang\String $password The password to set
     *
     * @return void
     */
    public function setPassword(String $password)
    {
        $this->password = $password;
    }

    /**
     * Return's the user's password.
     *
     * @return \AppserverIo\Lang\String The user's password
     */
    public function getPassword()
    {
        return $this->password;
    }
}
