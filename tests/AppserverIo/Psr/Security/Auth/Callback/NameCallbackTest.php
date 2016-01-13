<?php

/**
 * AppserverIo\Psr\Security\Auth\Callback\NameCallbackTest
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

namespace AppserverIo\Psr\Security\Auth\Callback;

use AppserverIo\Lang\String;

/**
 * Test for the name callback implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/application
 * @link      http://www.appserver.io
 */
class NameCallbackTest extends \PHPUnit_Framework_TestCase
{

    /**
     * The name callback to be tested.
     *
     * @var \AppserverIo\Psr\Security\Auth\Callback\NameCallback
     */
    protected $nameCallback;

    /**
     * Initializes the test case.
     *
     * @return void
     */
    protected function setUp()
    {
        $this->nameCallback = new NameCallback();
    }

    /**
     * Test if the callback constructor works as expected.
     *
     * @return void
     */
    public function testConstructor()
    {
        $this->assertEquals(new String(NameCallback::DEFAULT_NAME), $this->nameCallback->getDefaultName());
        $this->assertNull($this->nameCallback->getName());
    }

    /**
     * Test if the callback name setter/getter works as expected.
     *
     * @return void
     */
    public function testSetGetName()
    {
        $this->nameCallback->setName($name = new String(__CLASS__));
        $this->assertSame($name, $this->nameCallback->getName());
    }

    /**
     * Test if the callback default name setter/getter works as expected.
     *
     * @return void
     */
    public function testSetGetDefaultName()
    {
        $this->nameCallback->setDefaultName($defaultName = new String(__CLASS__));
        $this->assertSame($defaultName, $this->nameCallback->getDefaultName());
    }
}
