<?php

/**
 * AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface
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
 * Interface for a security domain DTO implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */
interface SecurityDomainConfigurationInterface
{

    /**
     * Return's the security domain name.
     *
     * @return string The security domain name
     */
    public function getName();

    /**
     * Return's the authentication configuration.
     *
     * @return \AppserverIo\Psr\Security\Auth\Login\AuthConfigurationInterface The authentication configuration
     */
    public function getAuthConfig();
}
