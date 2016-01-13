<?php

/**
 * AppserverIo\Psr\Security\Auth\Callback\PasswordCallbackTest
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
 * Test for the password callback implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/application
 * @link      http://www.appserver.io
 */
class PasswordCallbackTest extends \PHPUnit_Framework_TestCase
{

    /**
     * The password callback to be tested.
     *
     * @var \AppserverIo\Psr\Security\Auth\Callback\PasswordCallback
     */
    protected $passwordCallback;

    /**
     * Initializes the test case.
     *
     * @return void
     */
    protected function setUp()
    {
        $this->passwordCallback = new PasswordCallback();
    }

    /**
     * Test if the callback constructor works as expected.
     *
     * @return void
     */
    public function testConstructor()
    {
        $this->assertNull($this->passwordCallback->getPassword());
    }

    /**
     * Test if the callback password setter/getter works as expected.
     *
     * @return void
     */
    public function testSetGetPassword()
    {
        $this->passwordCallback->setPassword($password = new String(__CLASS__));
        $this->assertSame($password, $this->passwordCallback->getPassword());
    }
}
