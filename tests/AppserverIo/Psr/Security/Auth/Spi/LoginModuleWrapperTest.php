<?php

/**
 * AppserverIo\Psr\Security\Auth\Spi\LoginModuleWrapperTest
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

namespace AppserverIo\Psr\Security\Auth\Spi;

/**
 * Test for the login module wrapper implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/application
 * @link      http://www.appserver.io
 */
class LoginModuleWrapperTest extends \PHPUnit_Framework_TestCase
{

    /**
     * The password callback to be tested.
     *
     * @var \AppserverIo\Psr\Security\Auth\Spi\LoginModuleWrapper
     */
    protected $wrapper;

    /**
     * Initializes the test case.
     *
     * @return void
     */
    protected function setUp()
    {
        $this->wrapper = new LoginModuleWrapper();
    }

    /**
     * Test the wrapper's abort() method.
     *
     * @return void
     */
    public function testAbort()
    {

        // prepare the wrapped login module
        $mockLoginModule = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $mockLoginModule->expects($this->once())
            ->method('abort')
            ->willReturn(true);

        // inject the login module mock
        $this->wrapper->injectLoginModule($mockLoginModule);

        // invoke the abort() method
        $this->assertTrue($this->wrapper->abort());
    }

    /**
     * Test the wrapper's login() method.
     *
     * @return void
     */
    public function testLogin()
    {

        // prepare the wrapped login module
        $mockLoginModule = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $mockLoginModule->expects($this->once())
            ->method('login')
            ->willReturn(true);

        // inject the login module mock
        $this->wrapper->injectLoginModule($mockLoginModule);

        // invoke the login() method
        $this->assertTrue($this->wrapper->login());
    }

    /**
     * Test the wrapper's logout() method.
     *
     * @return void
     */
    public function testLogout()
    {

        // prepare the wrapped login module
        $mockLoginModule = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $mockLoginModule->expects($this->once())
            ->method('logout')
            ->willReturn(true);

        // inject the login module mock
        $this->wrapper->injectLoginModule($mockLoginModule);

        // invoke the logout() method
        $this->assertTrue($this->wrapper->logout());
    }

    /**
     * Test the wrapper's abort() method.
     *
     * @return void
     */
    public function testCommit()
    {

        // prepare the wrapped login module
        $mockLoginModule = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $mockLoginModule->expects($this->once())
            ->method('commit')
            ->willReturn(true);

        // inject the login module mock
        $this->wrapper->injectLoginModule($mockLoginModule);

        // invoke the commit() method
        $this->assertTrue($this->wrapper->commit());
    }

    /**
     * Test the wrapper's initialize() method.
     *
     * @return void
     */
    public function testInitialize()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');
        $sharedStateMock = $this->getMock('AppserverIo\Collections\HashMap');
        $paramsMock = $this->getMock('AppserverIo\Collections\HashMap');

        // prepare the wrapped login module
        $mockLoginModule = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $mockLoginModule->expects($this->once())
            ->method('initialize')
            ->willReturn(true);

        // inject the login module mock
        $this->wrapper->injectLoginModule($mockLoginModule);

        // invoke the initialize() method
        $this->assertTrue($this->wrapper->initialize($subjectMock, $callbackHandlerMock, $sharedStateMock, $paramsMock));
    }
}
