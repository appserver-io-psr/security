<?php

/**
 * AppserverIo\Psr\Security\Auth\Callback\LoginContextTest
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

namespace AppserverIo\Psr\Security\Auth\Login;

use AppserverIo\Psr\Security\Auth\Subject;
use AppserverIo\Lang\String;
use AppserverIo\Collections\HashMap;
use AppserverIo\Psr\Security\Auth\Login\Mock\MockLoginContext;

/**
 * Test for the login context implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/application
 * @link      http://www.appserver.io
 */
class LoginContextTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Test if the callback constructor works as expected.
     *
     * @return void
     */
    public function testConstructor()
    {

        // prepare the login module configuration mock
        $loginModuleConfigurationMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\LoginModuleConfigurationInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\LoginModuleConfigurationInterface'))
            ->getMock();
        $loginModuleConfigurationMock
            ->expects($this->once())
            ->method('getType')
            ->willReturn('LoginModules\MyLoginModuleImpl');
        $loginModuleConfigurationMock
            ->expects($this->once())
            ->method('getParamsAsArray')
            ->willReturn(array('principalClass' => 'Principals\MyPrincipalImp'));
        $loginModuleConfigurationMock
            ->expects($this->once())
            ->method('getFlag')
            ->willReturn(LoginModuleConfigurationInterface::REQUIRED);

        // prepare the auth configuration mock
        $authConfigurationMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\AuthConfigurationInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\AuthConfigurationInterface'))
            ->getMock();
        $authConfigurationMock
            ->expects($this->once())
            ->method('getLoginModules')
            ->willReturn(array($loginModuleConfigurationMock));

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');
        $configurationMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface'))
            ->getMock();
        $configurationMock
            ->expects($this->once())
            ->method('getAuthConfig')
            ->willReturn($authConfigurationMock);

        // initialize a new test instance
        $loginContext = new LoginContext($subjectMock, $callbackHandlerMock, $configurationMock);

        // test the subject
        $this->assertSame($loginContext->getSubject(), $subjectMock);
    }

    /**
     * Test the login() method without any configured login module.
     *
     * @return void
     */
    public function testLoginSuccessfullWithoutAnyLoginModule()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');
        $configurationMock = $this->getMock('AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface');

        // initialize a new test instance
        $loginContext = new LoginContext($subjectMock, $callbackHandlerMock, $configurationMock);

        // test the login() method
        $this->assertNull($loginContext->login());
    }

    /**
     * Test the login() method successfull configured with two REQUIRED login modules.
     *
     * @return void
     */
    public function testLoginSuccessfullWithTwoRequiredLoginModules()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');

        // prepare the first module info mock
        $moduleInfoOneMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('getType')
            ->willReturn(new String('LoginModules\LoginModuleOne'));
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('getParams')
            ->willReturn($paramsMock = $this->getMock('AppserverIo\Collections\HashMap'));
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('hasControlFlag')
            ->withConsecutive(new String(LoginModuleConfigurationInterface::REQUISITE), new String(LoginModuleConfigurationInterface::REQUIRED))
            ->willReturnOnConsecutiveCalls(false, true);

        // prepare the module info mock
        $moduleInfoTwoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoTwoMock
            ->expects($this->once())
            ->method('getType')
            ->willReturn(new String('LoginModules\LoginModuleTwo'));
        $moduleInfoTwoMock
            ->expects($this->once())
            ->method('getParams')
            ->willReturn($paramsMock = $this->getMock('AppserverIo\Collections\HashMap'));
        $moduleInfoTwoMock
            ->expects($this->once())
            ->method('hasControlFlag')
            ->withConsecutive(new String(LoginModuleConfigurationInterface::REQUISITE), new String(LoginModuleConfigurationInterface::REQUIRED))
            ->willReturnOnConsecutiveCalls(false, true);

        // prepare the mock for the shared state
        $sharedStateMock = $this->getMock('AppserverIo\Collections\HashMap');

        // prepare the login module mock
        $loginModuleOneMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleOneMock
            ->expects($this->once())
            ->method('initialize')
            ->with($subjectMock, $callbackHandlerMock, $sharedStateMock, $paramsMock);
        $loginModuleOneMock
            ->expects($this->once())
            ->method('login')
            ->willReturn(true);

        // prepare the login module mock
        $loginModuleTwoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleTwoMock
            ->expects($this->once())
            ->method('initialize')
            ->with($subjectMock, $callbackHandlerMock, $sharedStateMock, $paramsMock);
        $loginModuleTwoMock
            ->expects($this->once())
            ->method('login')
            ->willReturn(true);

        // prepare the login context mock
        $loginContextMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\LoginContext')
            ->setMethods(array('getModuleStack', 'createLoginModuleInstance', 'getSharedState', 'getCallbackHandler', 'getSubject'))
            ->disableOriginalConstructor()
            ->getMock();
        $loginContextMock
            ->expects($this->once())
            ->method('getModuleStack')
            ->willReturn(array($moduleInfoOneMock, $moduleInfoTwoMock));
        $loginContextMock
            ->expects($this->exactly(2))
            ->method('getSharedState')
            ->willReturn($sharedStateMock);
        $loginContextMock
            ->expects($this->exactly(2))
            ->method('getCallbackHandler')
            ->willReturn($callbackHandlerMock);
        $loginContextMock
            ->expects($this->exactly(2))
            ->method('getSubject')
            ->willReturn($subjectMock);
        $loginContextMock
            ->expects($this->exactly(2))
            ->method('createLoginModuleInstance')
            ->withConsecutive(new String('LoginModules\LoginModuleOne'), new String('LoginModules\LoginModuleTwo'))
            ->willReturnOnConsecutiveCalls($loginModuleOneMock, $loginModuleTwoMock);

        // test the login() method
        $this->assertNull($loginContextMock->login());
    }

    /**
     * Test the login() method fails with one configured login module.
     *
     * @return void
     * @expectedException AppserverIo\Psr\Security\Auth\Login\LoginException
     */
    public function testLoginExceptionWithOneRequiredLoginModule()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');

        // prepare the module info mock
        $moduleInfoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoMock
            ->expects($this->once())
            ->method('getType')
            ->willReturn(new String('\stdClass'));
        $moduleInfoMock
            ->expects($this->once())
            ->method('getParams')
            ->willReturn($paramsMock = $this->getMock('AppserverIo\Collections\HashMap'));
        $moduleInfoMock
            ->expects($this->exactly(2))
            ->method('hasControlFlag')
            ->withConsecutive(new String(LoginModuleConfigurationInterface::REQUISITE), new String(LoginModuleConfigurationInterface::REQUIRED))
            ->willReturnOnConsecutiveCalls(false, true);

        // prepare the mock for the shared state
        $sharedStateMock = $this->getMock('AppserverIo\Collections\HashMap');

        // prepare the login module mock
        $loginModuleMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleMock
            ->expects($this->once())
            ->method('initialize')
            ->with($subjectMock, $callbackHandlerMock, $sharedStateMock, $paramsMock);
        $loginModuleMock
            ->expects($this->once())
            ->method('login')
            ->willReturn(false);
        $loginModuleMock
            ->expects($this->once())
            ->method('abort')
            ->willReturn(true);

        // prepare the login context mock
        $loginContextMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\LoginContext')
            ->setMethods(array('getModuleStack', 'createLoginModuleInstance', 'getSharedState', 'getCallbackHandler', 'getSubject'))
            ->disableOriginalConstructor()
            ->getMock();
        $loginContextMock
            ->expects($this->once())
            ->method('getModuleStack')
            ->willReturn(array($moduleInfoMock));
        $loginContextMock
            ->expects($this->once())
            ->method('getSharedState')
            ->willReturn($sharedStateMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getCallbackHandler')
            ->willReturn($callbackHandlerMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getSubject')
            ->willReturn($subjectMock);
        $loginContextMock
            ->expects($this->once())
            ->method('createLoginModuleInstance')
            ->willReturn($loginModuleMock);

        // test the login() method
        $this->assertNull($loginContextMock->login());
    }

    /**
     * Test the login() method successfull configured with two, one of it flagged as SUFFICIENT, login modules.
     *
     * @return void
     */
    public function testLoginSuccessfullWithTwoAndOneSufficientLoginModules()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');

        // prepare the first module info mock
        $moduleInfoOneMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('getType')
            ->willReturn(new String('LoginModules\LoginModuleOne'));
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('getParams')
            ->willReturn($paramsMock = $this->getMock('AppserverIo\Collections\HashMap'));
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('hasControlFlag')
            ->with(new String(LoginModuleConfigurationInterface::SUFFICIENT))
            ->willReturn(true);

        // prepare the module info mock
        $moduleInfoTwoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoTwoMock
            ->expects($this->never())
            ->method('getType');
        $moduleInfoTwoMock
            ->expects($this->never())
            ->method('getParams');
        $moduleInfoTwoMock
            ->expects($this->never())
            ->method('hasControlFlag');

        // prepare the mock for the shared state
        $sharedStateMock = $this->getMock('AppserverIo\Collections\HashMap');

        // prepare the login module mock
        $loginModuleOneMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleOneMock
            ->expects($this->once())
            ->method('initialize')
            ->with($subjectMock, $callbackHandlerMock, $sharedStateMock, $paramsMock);
        $loginModuleOneMock
            ->method('login')
            ->willReturn(true);

        // prepare the login module mock
        $loginModuleTwoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleTwoMock
            ->expects($this->never())
            ->method('initialize');
        $loginModuleTwoMock
            ->expects($this->never())
            ->method('login');

        // prepare the login context mock
        $loginContextMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\LoginContext')
            ->setMethods(array('getModuleStack', 'createLoginModuleInstance', 'getSharedState', 'getCallbackHandler', 'getSubject'))
            ->disableOriginalConstructor()
            ->getMock();
        $loginContextMock
            ->expects($this->once())
            ->method('getModuleStack')
            ->willReturn(array($moduleInfoOneMock, $moduleInfoTwoMock));
        $loginContextMock
            ->expects($this->once())
            ->method('getSharedState')
            ->willReturn($sharedStateMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getCallbackHandler')
            ->willReturn($callbackHandlerMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getSubject')
            ->willReturn($subjectMock);
        $loginContextMock
            ->expects($this->once())
            ->method('createLoginModuleInstance')
            ->with(new String('LoginModules\LoginModuleOne'))
            ->willReturn($loginModuleOneMock);

        // test the login() method
        $this->assertNull($loginContextMock->login());
    }

    /**
     * Test the login() method failed configured with two, one of it flagged as REQUISITE, login modules.
     *
     * @return void
     * @expectedException AppserverIo\Psr\Security\Auth\Login\LoginException
     */
    public function testLoginExceptionWithTwoAndOneRequisiteLoginModules()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');

        // prepare the first module info mock
        $moduleInfoOneMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('getType')
            ->willReturn(new String('LoginModules\LoginModuleOne'));
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('getParams')
            ->willReturn($paramsMock = $this->getMock('AppserverIo\Collections\HashMap'));
        $moduleInfoOneMock
            ->expects($this->once())
            ->method('hasControlFlag')
            ->with(new String(LoginModuleConfigurationInterface::REQUISITE))
            ->willReturn(true);

        // prepare the module info mock
        $moduleInfoTwoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoTwoMock
            ->expects($this->never())
            ->method('getType');
        $moduleInfoTwoMock
            ->expects($this->never())
            ->method('getParams');
        $moduleInfoTwoMock
            ->expects($this->never())
            ->method('hasControlFlag');

        // prepare the mock for the shared state
        $sharedStateMock = $this->getMock('AppserverIo\Collections\HashMap');

        // prepare the login module mock
        $loginModuleOneMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleOneMock
            ->expects($this->once())
            ->method('initialize')
            ->with($subjectMock, $callbackHandlerMock, $sharedStateMock, $paramsMock);
        $loginModuleOneMock
            ->method('login')
            ->willReturn(false);

        // prepare the login module mock
        $loginModuleTwoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleTwoMock
            ->expects($this->never())
            ->method('initialize');
        $loginModuleTwoMock
            ->expects($this->never())
            ->method('login');

        // prepare the login context mock
        $loginContextMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\LoginContext')
            ->setMethods(array('getModuleStack', 'createLoginModuleInstance', 'getSharedState', 'getCallbackHandler', 'getSubject'))
            ->disableOriginalConstructor()
            ->getMock();
        $loginContextMock
            ->expects($this->once())
            ->method('getModuleStack')
            ->willReturn(array($moduleInfoOneMock, $moduleInfoTwoMock));
        $loginContextMock
            ->expects($this->once())
            ->method('getSharedState')
            ->willReturn($sharedStateMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getCallbackHandler')
            ->willReturn($callbackHandlerMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getSubject')
            ->willReturn($subjectMock);
        $loginContextMock
            ->expects($this->once())
            ->method('createLoginModuleInstance')
            ->with(new String('LoginModules\LoginModuleOne'))
            ->willReturn($loginModuleOneMock);

        // test the login() method
        $this->assertNull($loginContextMock->login());
    }

    /**
     * Test the successfull logout with one configured login module.
     *
     * @return void
     */
    public function testLogoutSuccessfullWithOneRequiredLoginModule()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');

        // prepare the module info mock
        $moduleInfoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoMock
            ->expects($this->once())
            ->method('getType')
            ->willReturn(new String('\stdClass'));
        $moduleInfoMock
            ->expects($this->once())
            ->method('getParams')
            ->willReturn($paramsMock = $this->getMock('AppserverIo\Collections\HashMap'));

        // prepare the mock for the shared state
        $sharedStateMock = $this->getMock('AppserverIo\Collections\HashMap');

        // prepare the login module mock
        $loginModuleMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleMock
            ->expects($this->once())
            ->method('initialize')
            ->with($subjectMock, $callbackHandlerMock, $sharedStateMock, $paramsMock);
        $loginModuleMock
            ->expects($this->once())
            ->method('logout')
            ->willReturn(true);

        // prepare the login context mock
        $loginContextMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\LoginContext')
            ->setMethods(array('getModuleStack', 'createLoginModuleInstance', 'getSharedState', 'getCallbackHandler', 'getSubject'))
            ->disableOriginalConstructor()
            ->getMock();
        $loginContextMock
            ->expects($this->once())
            ->method('getModuleStack')
            ->willReturn(array($moduleInfoMock));
        $loginContextMock
            ->expects($this->once())
            ->method('getSharedState')
            ->willReturn($sharedStateMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getCallbackHandler')
            ->willReturn($callbackHandlerMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getSubject')
            ->willReturn($subjectMock);
        $loginContextMock
            ->expects($this->once())
            ->method('createLoginModuleInstance')
            ->willReturn($loginModuleMock);

        // test the login() method
        $this->assertNull($loginContextMock->logout());
    }

    /**
     * Test that logout fails with one configured login module.
     *
     * @return void
     * @expectedException AppserverIo\Psr\Security\Auth\Login\LoginException
     */
    public function testLogoutFailureWithOneRequiredLoginModule()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');

        // prepare the module info mock
        $moduleInfoMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\ModuleInfo')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Login\ModuleInfo'))
            ->disableOriginalConstructor()
            ->getMock();
        $moduleInfoMock
            ->expects($this->once())
            ->method('getType')
            ->willReturn(new String('\stdClass'));
        $moduleInfoMock
            ->expects($this->once())
            ->method('getParams')
            ->willReturn($paramsMock = $this->getMock('AppserverIo\Collections\HashMap'));

        // prepare the mock for the shared state
        $sharedStateMock = $this->getMock('AppserverIo\Collections\HashMap');

        // prepare the login module mock
        $loginModuleMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface')
            ->setMethods(get_class_methods('AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface'))
            ->getMock();
        $loginModuleMock
            ->expects($this->once())
            ->method('initialize')
            ->with($subjectMock, $callbackHandlerMock, $sharedStateMock, $paramsMock);
        $loginModuleMock
            ->expects($this->once())
            ->method('logout')
            ->willThrowException(new \Exception('Something went wrong!'));

        // prepare the login context mock
        $loginContextMock = $this->getMockBuilder('AppserverIo\Psr\Security\Auth\Login\LoginContext')
            ->setMethods(array('getModuleStack', 'createLoginModuleInstance', 'getSharedState', 'getCallbackHandler', 'getSubject'))
            ->disableOriginalConstructor()
            ->getMock();
        $loginContextMock
            ->expects($this->once())
            ->method('getModuleStack')
            ->willReturn(array($moduleInfoMock));
        $loginContextMock
            ->expects($this->once())
            ->method('getSharedState')
            ->willReturn($sharedStateMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getCallbackHandler')
            ->willReturn($callbackHandlerMock);
        $loginContextMock
            ->expects($this->once())
            ->method('getSubject')
            ->willReturn($subjectMock);
        $loginContextMock
            ->expects($this->once())
            ->method('createLoginModuleInstance')
            ->willReturn($loginModuleMock);

        // test the login() method
        $this->assertNull($loginContextMock->logout());
    }

    /**
     * Test the instanciation of a new login modules instance.
     *
     * @return void
     */
    public function testCreateLoginModuleInstance()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');
        $configurationMock = $this->getMock('AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface');

        // initialize a new test instance
        $loginContext = new MockLoginContext($subjectMock, $callbackHandlerMock, $configurationMock);

        // test the createLoginModuleInstance() method
        $this->assertInstanceOf(
            'AppserverIo\Psr\Security\Auth\Spi\LoginModuleInterface',
            $loginContext->createLoginModuleInstance(new String('AppserverIo\Psr\Security\Auth\Spi\LoginModuleWrapper'))
        );
    }

    /**
     * Test the getSharedState() method.
     *
     * @return void
     */
    public function testGetSharedState()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');
        $configurationMock = $this->getMock('AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface');

        // initialize a new test instance
        $loginContext = new MockLoginContext($subjectMock, $callbackHandlerMock, $configurationMock);

        // test the getSharedState() method
        $this->assertInstanceOf('AppserverIo\Collections\HashMap', $loginContext->getSharedState());
    }

    /**
     * Test the getCallbackHandler() method.
     *
     * @return void
     */
    public function testGetCallbackHandler()
    {

        // prepare the mocks for the login context
        $subjectMock = $this->getMock('AppserverIo\Psr\Security\Auth\Subject');
        $callbackHandlerMock = $this->getMock('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface');
        $configurationMock = $this->getMock('AppserverIo\Psr\Security\Auth\Login\SecurityDomainConfigurationInterface');

        // initialize a new test instance
        $loginContext = new MockLoginContext($subjectMock, $callbackHandlerMock, $configurationMock);

        // test the getCallbackHandler() method
        $this->assertInstanceOf('AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface', $loginContext->getCallbackHandler());
    }
}
