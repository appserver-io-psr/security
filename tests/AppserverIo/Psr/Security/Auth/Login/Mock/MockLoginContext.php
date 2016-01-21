<?php

/**
 * AppserverIo\Psr\Security\Auth\Login\Mock\MockLoginContext
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
 * @link      https://github.com/appserver-io-psr/application
 * @link      http://www.appserver.io
 */

namespace AppserverIo\Psr\Security\Auth\Login\Mock;

use AppserverIo\Lang\String;
use AppserverIo\Psr\Security\Auth\Login\LoginContext;

/**
 * A mock implementation for a login context.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/application
 * @link      http://www.appserver.io
 */
class MockLoginContext extends LoginContext
{

    /**
     * Return's the login context's shared state map.
     *
     * @return \AppserverIo\Collections\HashMap The map with the shared state data
     */
    public function getSharedState()
    {
        return parent::getSharedState();
    }

    /**
     * Return's the callback handler used by the login modules to communicate with the user.
     *
     * @return \AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface The callback handler
     */
    public function getCallbackHandler()
    {
        return parent::getCallbackHandler();
    }

    /**
     * Create's a new instance of the login module with the passed class name.
     *
     * @param \AppserverIo\Lang\String $className The login module class name
     *
     * @return \AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface The login module instance
     */
    public function createLoginModuleInstance(String $className)
    {
        return parent::createLoginModuleInstance($className);
    }
}
