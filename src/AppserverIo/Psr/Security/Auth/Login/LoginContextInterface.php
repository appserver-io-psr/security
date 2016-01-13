<?php

/**
 * AppserverIo\Psr\Security\Auth\Login\LoginContextInterface
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

/**
 * The LoginContext class describes the basic methods used to authenticate Subjects and provides a way
 * to develop an application independent of the underlying authentication technology. A Configuration
 * specifies the authentication technology, or LoginModule, to be used with a particular application.
 * Different LoginModules can be plugged in under an application without requiring any modifications to
 * the application itself.
 *
 * In addition to supporting pluggable authentication, this class also supports the notion of stacked
 * authentication. Applications may be configured to use more than one LoginModule. For example, one could
 * configure both a Kerberos LoginModule and a smart card LoginModule under an application
 *
 * A typical caller instantiates a LoginContext with a name and a CallbackHandler. LoginContext uses the
 * name as the index into a Configuration to determine which LoginModules should be used, and which ones
 * must succeed in order for the overall authentication to succeed. The CallbackHandler is passed to the
 * underlying LoginModules so they may communicate and interact with users (prompting for a username and
 * password via a graphical user interface, for example).
 *
 * Once the caller has instantiated a LoginContext, it invokes the login method to authenticate a Subject.
 * The login method invokes the configured modules to perform their respective types of authentication
 * (username/password, smart card pin verification, etc.). Note that the LoginModules will not attempt
 * authentication retries nor introduce delays if the authentication fails. Such tasks belong to the
 * LoginContext caller.
 *
 * If the login method returns without throwing an exception, then the overall authentication succeeded.
 * The caller can then retrieve the newly authenticated Subject by invoking the getSubject method. Principals
 * and Credentials associated with the Subject may be retrieved by invoking the Subject's respective
 * getPrincipals, getPublicCredentials, and getPrivateCredentials methods
 *
 * To logout the Subject, the caller calls the logout method. As with the login method, this logout method
 * invokes the logout method for the configured modules
 *
 * A LoginContext should not be used to authenticate more than one Subject. A separate LoginContext should
 * be used to authenticate each different Subject.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io-psr/security
 * @link      http://www.appserver.io
 */
interface LoginContextInterface
{

    /**
     * Perform the authentication.
     *
     * This method invokes the login method for each LoginModule configured for the name specified to
     * the LoginContext constructor, as determined by the login Configuration. Each LoginModule then
     * performs its respective type of authentication (username/password, smart card pin verification,
     * etc.).
     *
     * This method completes a 2-phase authentication process by calling each configured LoginModule's
     * commit method if the overall authentication succeeded (the relevant REQUIRED, REQUISITE, SUFFICIENT,
     * and OPTIONAL LoginModules succeeded), or by calling each configured LoginModule's abort method if
     * the overall authentication failed. If authentication succeeded, each successful LoginModule's commit
     * method associates the relevant Principals and Credentials with the Subject. If authentication failed,
     * each LoginModule's abort method removes/destroys any previously stored state.
     *
     * If the commit phase of the authentication process fails, then the overall authentication fails and
     * this method invokes the abort method for each configured LoginModule.
     *
     * If the abort phase fails for any reason, then this method propagates the original exception thrown
     * either during the login phase or the commit phase. In either case, the overall authentication fails.
     *
     * In the case where multiple LoginModules fail, this method propagates the exception raised by the
     * first LoginModule which failed.
     *
     * Note that if this method enters the abort phase (either the login or commit phase failed), this method
     * invokes all LoginModules configured for the application regardless of their respective Configuration
     * flag parameters. Essentially this means that Requisite and Sufficient semantics are ignored during the
     * abort phase. This guarantees that proper cleanup and state restoration can take place.
     *
     * @return void
     * @throw \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if the authentication fails
     */
    public function login();

    /**
     * Logout the Subject.
     *
     * This method invokes the logout method for each LoginModule configured for this LoginContext. Each
     * LoginModule performs its respective logout procedure which may include removing/destroying Principal
     * and Credential information from the Subject and state cleanup.
     *
     * Note that this method invokes all LoginModules configured for the application regardless of their
     * respective Configuration flag parameters. Essentially this means that Requisite and Sufficient semantics
     * are ignored for this method. This guarantees that proper cleanup and state restoration can take place.
     *
     * @return void
     * @throw \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if the logout fails
     */
    public function logout();

    /**
     * Return the authenticated subject.
     *
     * If the caller specified a Subject to this LoginContext's constructor, this method returns the
     * caller-specified Subject. If a Subject was not specified and authentication succeeds, this method returns
     * the Subject instantiated and used for authentication by this LoginContext. If a Subject was not specified,
     * and authentication fails or has not been attempted, this method returns null.
     *
     * @return \AppserverIo\Psr\Security\Auth\Subject The authenticated Subject
     */
    public function getSubject();
}
