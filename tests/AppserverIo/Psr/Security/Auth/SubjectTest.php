<?php

/**
 * AppserverIo\Psr\Security\Auth\SubjectTest
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

namespace AppserverIo\Psr\Security\Auth;

use AppserverIo\Collections\ArrayList;
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
class SubjectTest extends \PHPUnit_Framework_TestCase
{

    /**
     * The subject to be tested.
     *
     * @var \AppserverIo\Psr\Security\Auth\Subject
     */
    protected $subject;

    /**
     * Initializes the test case.
     *
     * @return void
     */
    protected function setUp()
    {
        $this->subject = new Subject();
    }

    /**
     * Test if the constructor works as expected.
     *
     * @return void
     */
    public function testConstructor()
    {
        $this->assertFalse($this->subject->isReadOnly());
        $this->assertInstanceOf('AppserverIo\Collections\CollectionInterface', $this->subject->getPrincipals());
        $this->assertInstanceOf('AppserverIo\Collections\CollectionInterface', $this->subject->getPublicCredentials());
        $this->assertInstanceOf('AppserverIo\Collections\CollectionInterface', $this->subject->getPrivateCredentials());
    }

    /**
     * Test if the constructor works as expected.
     *
     * @return void
     */
    public function testConstructorWithPassedValues()
    {

        // initialize the subject with the passed values
        $subject = new Subject(
            $principals = new ArrayList(),
            $publicCredentials = new ArrayList(),
            $privateCredentials = new ArrayList(),
            true
        );

        // assert the values
        $this->assertTrue($subject->isReadOnly());
        $this->assertSame($principals, $subject->getPrincipals());
        $this->assertSame($publicCredentials, $subject->getPublicCredentials());
        $this->assertSame($privateCredentials, $subject->getPrivateCredentials());
    }

    /**
     * Test the setter for the read only setter.
     *
     * @return void
     */
    public function testSetReadOnly()
    {
        $this->subject->setReadOnly();
        $this->assertTrue($this->subject->isReadOnly());
    }

    /**
     * Test the serialize/unserialize methods.
     *
     * @return void
     */
    public function testSerializeUnserialize()
    {

        // create a mock principal
        $mockPrincipal = $this->getMock('AppserverIo\Psr\Security\PrincipalInterface');

        // initialize the subject with the passed principals
        $subject = new Subject(
            new ArrayList(array($mockPrincipal)),
            new ArrayList(array(new String('publicKey'))),
            new ArrayList(array(new String('privateKey'))),
            true
        );

        // serialize the subject
        $serialized = serialize($subject);
        $unserialized = unserialize($serialized);

        // assert that unserialize restores the principals only
        $this->assertEquals($subject->getPrincipals(), $unserialized->getPrincipals());
        $this->assertCount(0, $unserialized->getPublicCredentials());
        $this->assertCount(0, $unserialized->getPrivateCredentials());
        $this->assertTrue($unserialized->isReadOnly());
    }
}
