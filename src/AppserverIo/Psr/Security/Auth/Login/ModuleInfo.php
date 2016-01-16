<?php

/**
 * AppserverIo\Psr\Security\Auth\Login\LoginException
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

namespace AppserverIo\Psr\Security\Auth\Login;

use AppserverIo\Lang\String;
use AppserverIo\Collections\HashMap;

/**
 * Contain's information about a login module's configuration.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/security
 * @link      http://www.appserver.io
 */
class ModuleInfo
{

    /**
     * The login module's class name.
     *
     * @var \AppserverIo\Lang\String
     */
    protected $type;

    /**
     * The login module's initialization parameters.
     *
     * @var \AppserverIo\Collections\HashMap
     */
    protected $params;

    /**
     * Initializes the instance with the login module name and initialization params.
     *
     * @param \AppserverIo\Lang\String         $type   The login module class name
     * @param \AppserverIo\Collections\HashMap $params The parameters for the initialize() method
     */
    public function __construct(String $type, HashMap $params)
    {
        $this->type = $type;
        $this->params = $params;
    }

    /**
     * Return's the login modules class name.
     *
     * @return \AppserverIo\Lang\String The class name
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Return's the login modules initialization parameters.
     *
     * @return \AppserverIo\Collections\HashMap The parameters
     */
    public function getParams()
    {
        return $this->params;
    }
}
