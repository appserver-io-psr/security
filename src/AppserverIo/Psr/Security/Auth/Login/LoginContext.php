<?php

/**
 * AppserverIo\Psr\Security\Auth\Login\LoginContext
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
use AppserverIo\Collections\ArrayList;
use AppserverIo\Lang\Reflection\ReflectionClass;
use AppserverIo\Psr\Security\Auth\Subject;
use AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface;
use AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface;
use AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface;

/**
 * A generic LoginContext implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/security
 * @link      http://www.appserver.io
 */
class LoginContext implements LoginContextInterface
{

    /**
     * The subject to authenticate.
     *
     * @var \AppserverIo\Psr\Security\Auth\Subject
     */
    protected $subject;

    /**
     * The callback handler used by the login modules to communicate with the user.
     *
     * @var \AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface
     */
    protected $callbackHandler;

    /**
     * Configuration with the login modules to perform the authentication.
     *
     * @var \AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface
     */
    protected $configuration;

    /**
     * The ArrayList with the module configuration.
     *
     * @var \AppserverIo\Collections\ArrayList
     */
    protected $moduleStack;

    /**
     * The HashMap to share the state between the login modules.
     *
     * @var \AppserverIo\Collections\HashMap
     */
    protected $sharedState;

    /**
     * TRUE if the login has been successful, else FALSE.
     *
     * @var boolean
     */
    protected $loginSucceeded = false;

    /**
     * Initialize the LoginContext with the passed objects.
     *
     * @param \AppserverIo\Psr\Security\Auth\Subject                                    $subject         The subject to authenticate
     * @param \AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface          $callbackHandler Used by the login modules to communicate with the user
     * @param \AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface $configuration   The configuration with the login modules to perform the authentication
     */
    public function __construct(
        Subject $subject,
        CallbackHandlerInterface $callbackHandler,
        SecurityDomainConfigurationInterface $configuration
    ) {

        // set the passed objects
        $this->subject = $subject;
        $this->callbackHandler = $callbackHandler;
        $this->configuration = $configuration;

        // initialize the collections
        $this->sharedState = new HashMap();
        $this->moduleStack = new ArrayList();

        // initialize the LoginContext
        $this->init();
    }

    /**
     * Return's the login context configuration.
     *
     * @return \AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface The configuration
     */
    protected function getConfiguration()
    {
        return $this->configuration;
    }

    /**
     * Add's the passed module info to the stack.
     *
     * @param \AppserverIo\Psr\Security\Auth\Login\ModuleInfo $moduleInfo The module info to add
     *
     * @return void
     */
    protected function addModuleInfo(ModuleInfo $moduleInfo)
    {
        $this->moduleStack->add($moduleInfo);
    }

    /**
     * Return's the stack with the module information.
     *
     * @return \AppserverIo\Collections\ArrayList The stack
     */
    protected function getModuleStack()
    {
        return $this->moduleStack;
    }

    /**
     * Initialize the LoginContext with the passed name.
     *
     * @return void
     */
    protected function init()
    {
        // load the authorization configuration for the apropriate security domain
        /** @var \AppserverIo\Psr\Security\Auth\Login\AuthConfigurationInterface $authConfiguration */
        if ($authConfiguration = $this->getConfiguration()->getAuthConfig()) {
            // prepare the login modules of the security domain
            /** @var \AppserverIo\Psr\Security\Auth\Login\LoginModuleConfigurationInterface $loginModule */
            foreach ($authConfiguration->getLoginModules() as $loginModule) {
                // load the login modules class name and initialization parameters
                $type = new String($loginModule->getType());
                $params = new HashMap($loginModule->getParamsAsArray());
                // add the module information to the stack
                $this->addModuleInfo(new ModuleInfo($type, $params));
            }
        }
    }

    /**
     * Perform the authentication.
     *
     * @return void
     * @throw \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if the authentication fails
     * @see \AppserverIo\Psr\Security\Auth\Login\LoginContextInterface::login()
     */
    public function login()
    {
        // login has NOT succeeded yet
        $failure = false;

        // create an array for the initialized login modules
        $loginModules = array();

        // process the login modules and try to authenticate the user
        /** @var \AppserverIo\Psr\Security\Auth\Login\ModuleInfo $moduleInfo */
        foreach ($this->getModuleStack() as $index => $moduleInfo) {
            try {
                // reflection the requested login module type
                $reflectionClass = new ReflectionClass($moduleInfo->getType()->stringValue());

                // initialize the login module and invoke the login() method
                /** @var \AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface $loginModules[$index] */
                $loginModules[$index] = $reflectionClass->newInstance();
                $loginModules[$index]->initialize($this->subject, $this->callbackHandler, $this->sharedState, $moduleInfo->getParams());

                // query whether or not the login attempt failed
                /* if ($loginModules[$index]->login() === false) {
                    if ($moduleInfo[$index]->hasControlFlag(REQUESITE)) {
                        throw new LoginException("REQUISITE module " . $moduleInfo[i]->getLoginModuleName() . " failed");
                    } elseif ($moduleInfo[$index]->hasControlFlag(REQUIRED)) {
                        $failure = true;
                    } else {
                        // do nothing
                    }

                } else {
                    $moduleInfo[$index]->hasControlFlag(SUFFICIENT);
                    break;
                } */

            } catch (LoginException $le) {
                $loginModules[$index]->abort();
                throw $le;
            }
        }

        // throw an exception if one of the RQUIRED login modules failed
        if ($this->failure === true) {
            throw new LoginException ("Not all REQUIRED modules succeeded");
        }

        // invoke the commit() method on the processed login modules
        foreach ($this->getModuleStack() as $indx => $moduleInfo) {
            $loginModules[$index]->commit();
        }
    }

    /**
     * Logout the Subject.
     *
     * @return void
     * @throw \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if the logout fails
     * @see \AppserverIo\Psr\Security\Auth\Login\LoginContextInterface::logout()
     */
    public function logout()
    {

    }

    /**
     * Return the authenticated subject.
     *
     * @return \AppserverIo\Psr\Security\Auth\Subject The authenticated Subject
     * @see \AppserverIo\Psr\Security\Auth\Login\LoginContextInterface::getSubject()
     */
    public function getSubject()
    {
        return $this->subject;
    }
}
