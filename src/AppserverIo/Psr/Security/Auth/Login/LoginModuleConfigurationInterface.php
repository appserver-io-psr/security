<?php

/**
 * AppserverIo\Psr\Security\Auth\Login\LoginModuleConfigurationInterface
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
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */

namespace AppserverIo\Psr\Security\Auth\Login;

/**
 * Interface for a login module DTO implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */
interface LoginModuleConfigurationInterface
{

    /**
     * The LoginModule is required to succeed. If it succeeds or fails, authentication still continues to
     * proceed down the LoginModule list.
     *
     * @var string
     */
    const REQUIRED = 'Required';

    /**
     * The LoginModule is required to succeed. If it succeeds, authentication continues down the LoginModule
     * list. If it fails, control immediately returns to the application (authentication does not proceed
     * down the LoginModule list).
     *
     * @var string
     */
    const REQUISITE = 'Requisite';

    /**
     * The LoginModule is not required to succeed.  If it does succeed, control immediately  returns to the
     * application (authentication does not proceed down the LoginModule list). If it fails, authentication
     * continues down the LoginModule list.
     *
     * @var string
     */
    const SUFFICIENT = 'Sufficient';

    /**
     * The LoginModule is not required to succeed.  If it succeeds or fails, authentication still continues
     * to proceed down the LoginModule list.
     *
     * @var string
     */
    const OPTIONAL = 'Optional';

    /**
     * Returns's the login module type.
     *
     * @return string The login module type
     */
    public function getType();

    /**
     * Return's the login module flag.
     *
     * @return string The login module flag
     */
    public function getFlag();

    /**
     * Array with the handler params to use.
     *
     * @return array The params
     */
    public function getParams();

    /**
     * Returns the param with the passed name casted to
     * the specified type.
     *
     * @param string $name The name of the param to be returned
     *
     * @return mixed The requested param casted to the specified type
     */
    public function getParam($name);

    /**
     * Returns the params casted to the defined type
     * as associative array.
     *
     * @return array The array with the casted params
     */
    public function getParamsAsArray();
}
