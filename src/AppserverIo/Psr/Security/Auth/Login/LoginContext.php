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
     * Return's the login context's shared state map.
     *
     * @return \AppserverIo\Collections\HashMap The map with the shared state data
     */
    protected function getSharedState()
    {
        return $this->sharedState;
    }

    /**
     * Return's the callback handler used by the login modules to communicate with the user.
     *
     * @return \AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface The callback handler
     */
    protected function getCallbackHandler()
    {
        return $this->callbackHandler;
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
                $controlFlag = new String($loginModule->getFlag());
                // add the module information to the stack
                $this->addModuleInfo(new ModuleInfo($type, $params, $controlFlag));
            }
        }
    }

    /**
     * Create's a new instance of the login module with the passed class name.
     *
     * @param \AppserverIo\Lang\String $className The login module class name
     *
     * @return \AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface The login module instance
     */
    protected function createLoginModuleInstance(String $className)
    {
        $reflectionClass = new ReflectionClass($className->stringValue());
        return $reflectionClass->newInstance();
    }

    /**
     * Perform the authentication.
     *
     * REQUIRED:   The login module is required to succeed for the authentication to be successful. If any required
     *             module fails, the authentication will fail. The remaining login modules in the stack will be called
     *             regardless of the outcome of the authentication.
     * REQUISITE:  The login module is required to succeed. If it succeeds, authentication continues down the login
     *             stack. If it fails, control immediately returns to the application.
     * SUFFICIENT: The login module is not required to succeed. If it does succeed, control immediately returns to the
     *             application. If it fails, authentication continues down the login stack.
     * OPTIONAL:   The login module is not required to succeed. Authentication still continues to proceed down the
     *             login stack regardless of whether the login module succeeds or fails.
     *
     * @return void
     * @throw \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if the authentication fails
     * @see \AppserverIo\Psr\Security\Auth\Login\LoginContextInterface::login()
     */
    public function login()
    {

        // login has NOT succeeded yet
        $failure = false;

        // the array containing the initialized login modules
        $loginModules = array();

        // process the login modules and try to authenticate the user
        /** @var \AppserverIo\Psr\Security\Auth\Login\ModuleInfo $moduleInfo */
        foreach ($this->getModuleStack() as $index => $moduleInfo) {
            try {
                // initialize the login module and invoke the login() method
                /** @var \AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface $loginModules[$index] */
                $loginModules[$index] = $this->createLoginModuleInstance($moduleInfo->getType());
                $loginModules[$index]->initialize($this->getSubject(), $this->getCallbackHandler(), $this->getSharedState(), $moduleInfo->getParams());

                // query whether or not the login attempt failed
                if ($loginModules[$index]->login() === true) {
                    // commit the login attempt
                    $loginModules[$index]->commit();
                    // if the login module has the SUFFICIENT flag, we stop processing
                    if ($moduleInfo->hasControlFlag(new String(LoginModuleConfigurationInterface::SUFFICIENT))) {
                        break;
                    }

                } else {
                    // we need to be aware of the login module's control flag
                    if ($moduleInfo->hasControlFlag(new String(LoginModuleConfigurationInterface::REQUISITE))) {
                        throw new LoginException(sprintf('REQUISITE module %s failed', get_class($loginModules[$index])));
                    } elseif ($moduleInfo->hasControlFlag(new String(LoginModuleConfigurationInterface::REQUIRED))) {
                        $failure = true;
                    } else {
                        // do nothing, because we're OPTIONAL or SUFFICIENT
                    }
                }

            } catch (LoginException $le) {
                // abort the login process
                $loginModules[$index]->abort();
                // re-throw the exception
                throw $le;
            }
        }

        // query whether or not one of the required login modules failed
        if ($failure === true) {
            // abort the REQUIRED login modules
            foreach ($loginModules as $loginModule) {
                $loginModule->abort();
            }
            // throw an exception if one of the REQUIRED login modules failed
            throw new LoginException('Not all REQUIRED modules succeeded');
        }
    }

    /**
     * Logout the subject.
     *
     * @return void
     * @throw \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if the logout fails
     * @see \AppserverIo\Psr\Security\Auth\Login\LoginContextInterface::logout()
     */
    public function logout()
    {

        // process the login modules and try to authenticate the user
        /** @var \AppserverIo\Psr\Security\Auth\Login\ModuleInfo $moduleInfo */
        foreach ($this->getModuleStack() as $moduleInfo) {
            try {
                // initialize the login module and invoke the logout() method
                /** @var \AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface $loginModule */
                $loginModule = $this->createLoginModuleInstance($moduleInfo->getType());
                $loginModule->initialize($this->getSubject(), $this->getCallbackHandler(), $this->getSharedState(), $moduleInfo->getParams());

                // query whether or not the login attempt failed
                $loginModule->logout();

            } catch (\Exception $e) {
                throw new LoginException($e->__toString());
            }
        }
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
