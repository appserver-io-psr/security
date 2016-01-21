<?php

/**
 * AppserverIo\Psr\Security\Auth\Callback\ModuleInfoTest
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

use AppserverIo\Lang\String;
use AppserverIo\Collections\HashMap;

/**
 * Test for the module info implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/application
 * @link      http://www.appserver.io
 */
class ModuleInfoTest extends \PHPUnit_Framework_TestCase
{

    /**
     * The password callback to be tested.
     *
     * @var \AppserverIo\Psr\Security\Auth\Login\ModuleInfo
     */
    protected $moduleInfo;

    /**
     * Initializes the test case.
     *
     * @return void
     */
    protected function setUp()
    {

        // initialize the parameters for the module information
        $type = new String('\LoginModules\MyLoginModule');
        $params = new HashMap(array('passwordStacking' => 'useFirstPass'));
        $controlFlag = new String(LoginModuleConfigurationInterface::REQUIRED);

        // initialize a new test instance
        $this->moduleInfo = new ModuleInfo($type, $params, $controlFlag);
    }

    /**
     * Test if the callback constructor works as expected.
     *
     * @return void
     */
    public function testConstructor()
    {
        $this->assertEquals($this->moduleInfo->getType(), new String('\LoginModules\MyLoginModule'));
        $this->assertEquals($this->moduleInfo->getParams(), new HashMap(array('passwordStacking' => 'useFirstPass')));
        $this->assertEquals($this->moduleInfo->getControlFlag(), new String(LoginModuleConfigurationInterface::REQUIRED));
    }

    /**
     * Test if the method to query the control flag works as expected.
     *
     * @return void
     */
    public function testHasControlFlag()
    {
        $this->assertTrue($this->moduleInfo->hasControlFlag(new String(LoginModuleConfigurationInterface::REQUIRED)));
    }
}
