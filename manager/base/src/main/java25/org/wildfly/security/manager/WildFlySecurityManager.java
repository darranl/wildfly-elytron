/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.manager;

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.net.InetAddress;
import java.security.AccessControlContext;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;
import java.util.PropertyPermission;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

import org.kohsuke.MetaInfServices;
import org.wildfly.common.Assert;
import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;
import org.wildfly.security.manager.action.ClearPropertyAction;
import org.wildfly.security.manager.action.GetClassLoaderAction;
import org.wildfly.security.manager.action.GetContextClassLoaderAction;
import org.wildfly.security.manager.action.GetEnvironmentAction;
import org.wildfly.security.manager.action.GetProtectionDomainAction;
import org.wildfly.security.manager.action.GetSystemPropertiesAction;
import org.wildfly.security.manager.action.ReadEnvironmentPropertyAction;
import org.wildfly.security.manager.action.ReadPropertyAction;
import org.wildfly.security.manager.action.SetContextClassLoaderAction;
import org.wildfly.security.manager.action.WritePropertyAction;
import org.wildfly.security.permission.PermissionVerifier;
import sun.misc.Unsafe;

import static java.lang.System.clearProperty;
import static java.lang.System.getProperties;
import static java.lang.System.getProperty;
import static java.lang.System.getSecurityManager;
import static java.lang.System.getenv;
import static java.lang.System.setProperty;
import static java.lang.Thread.currentThread;
import static java.security.AccessController.doPrivileged;
import static java.security.AccessController.getContext;
import static org.wildfly.security.manager.WildFlySecurityManagerPermission.doUncheckedPermission;
import static org.wildfly.security.manager._private.SecurityMessages.access;

/**
 * The security manager.  This security manager implementation can be switched on and off on a per-thread basis,
 * and additionally logs access violations in a way that should be substantially clearer than most JDK implementations.
 *
 * <p><strong>Java 25+ Note:</strong> This implementation provides a compatibility layer for code that depends on
 * SecurityManager APIs. On Java 25 and later, SecurityManager enforcement is disabled by the JVM. This class
 * maintains the API surface for backward compatibility but does not perform actual permission checks.</p>
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @deprecated SecurityManager is deprecated for removal in Java. This class is maintained for API compatibility
 *             but does not enforce permissions on Java 25+. Applications should migrate away from SecurityManager.
 */
@Deprecated(since = "2.8.5", forRemoval = true)
@MetaInfServices(SecurityManager.class)
public final class WildFlySecurityManager extends SecurityManager implements PermissionVerifier {


    /**
     * Construct a new instance.  If the caller does not have permission to do so, this method will throw an exception.
     *
     * @throws SecurityException if the caller does not have permission to create a security manager instance
     */
    public WildFlySecurityManager() throws SecurityException {
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public static void install() throws SecurityException {
        throw access.securityManagerMethodNotSupported("install");
    }


    /**
     * Determine whether the security manager is currently checking permissions.
     *
     * <p><strong>Java 25+ Note:</strong> Always returns {@code false} as SecurityManager enforcement
     * is disabled by the JVM on Java 25 and later.</p>
     *
     * @return {@code false} on Java 25+, indicating no permission checking is performed
     * @deprecated SecurityManager enforcement is disabled on Java 25+
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public static boolean isChecking() {
        // On Java 25+, SecurityManager enforcement is disabled by the JVM
        return false;
    }

    /**
     * Check if a permission is implied.
     *
     * <p><strong>Java 25+ Note:</strong> SecurityManager enforcement is disabled by the JVM on Java 25+.
     * This method throws UnsupportedOperationException to prevent accidental usage.</p>
     *
     * @param permission the permission to check (ignored)
     * @throws UnsupportedOperationException always thrown on Java 25+ to indicate SecurityManager is not functional
     * @deprecated SecurityManager enforcement is disabled on Java 25+
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public boolean implies(final Permission permission) {
        throw access.securityManagerMethodNotSupported("implies");
    }

    /**
     * Perform a permission check.
     *
     * <p><strong>Java 25+ Note:</strong> SecurityManager enforcement is disabled by the JVM on Java 25+.
     * This method throws UnsupportedOperationException to prevent accidental usage.</p>
     *
     * @param perm the permission to check (ignored)
     * @throws UnsupportedOperationException always thrown on Java 25+ to indicate SecurityManager is not functional
     * @deprecated SecurityManager enforcement is disabled on Java 25+
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkPermission(final Permission perm) throws SecurityException {
        throw access.securityManagerNotSupported();
    }

    /**
     * Perform a permission check.
     *
     * <p><strong>Java 25+ Note:</strong> SecurityManager enforcement is disabled by the JVM on Java 25+.
     * This method throws UnsupportedOperationException to prevent accidental usage.</p>
     *
     * @param perm the permission to check (ignored)
     * @param context the security context to use for the check (ignored)
     * @throws UnsupportedOperationException always thrown on Java 25+ to indicate SecurityManager is not functional
     * @deprecated SecurityManager enforcement is disabled on Java 25+
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkPermission(final Permission perm, final Object context) throws SecurityException {
        throw access.securityManagerNotSupported();
    }


    /**
     * Perform a permission check with an AccessControlContext.
     *
     * <p><strong>Java 25+ Note:</strong> SecurityManager enforcement is disabled by the JVM on Java 25+.
     * This method throws UnsupportedOperationException to prevent accidental usage.</p>
     *
     * @param perm the permission to check (ignored)
     * @param context the security context to use for the check (ignored)
     * @throws UnsupportedOperationException always thrown on Java 25+ to indicate SecurityManager is not functional
     * @deprecated SecurityManager enforcement is disabled on Java 25+
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkPermission(final Permission perm, final AccessControlContext context) throws SecurityException {
        throw access.securityManagerNotSupported();
    }

    /**
     * Find the protection domain in the given list which denies a permission.
     *
     * <p><strong>Java 25+ Note:</strong> SecurityManager enforcement is disabled by the JVM on Java 25+.
     * This method throws UnsupportedOperationException to prevent accidental usage.</p>
     *
     * @param permission the permission to test (ignored)
     * @param domains the protection domains to try (ignored)
     * @return never returns normally
     * @throws UnsupportedOperationException always thrown on Java 25+ to indicate SecurityManager is not functional
     * @deprecated SecurityManager enforcement is disabled on Java 25+
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public static ProtectionDomain findAccessDenial(final Permission permission, final ProtectionDomain... domains) {
        throw access.securityManagerMethodNotSupported("findAccessDenial");
    }

    /**
     * Try a permission check.
     *
     * <p><strong>Java 25+ Note:</strong> SecurityManager enforcement is disabled by the JVM on Java 25+.
     * This method throws UnsupportedOperationException to prevent accidental usage.</p>
     *
     * @param permission the permission to check (ignored)
     * @param domains the protection domains to try (ignored)
     * @return never returns normally
     * @throws UnsupportedOperationException always thrown on Java 25+ to indicate SecurityManager is not functional
     * @deprecated SecurityManager enforcement is disabled on Java 25+
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public static boolean tryCheckPermission(final Permission permission, final ProtectionDomain... domains) {
        throw access.securityManagerMethodNotSupported("tryCheckPermission");
    }



    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkCreateClassLoader() {
        throw access.securityManagerMethodNotSupported("checkCreateClassLoader");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkAccess(final Thread t) {
        throw access.securityManagerMethodNotSupported("checkAccess");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkAccess(final ThreadGroup g) {
        throw access.securityManagerMethodNotSupported("checkAccess");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkExit(final int status) {
        throw access.securityManagerMethodNotSupported("checkExit");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkExec(final String cmd) {
        throw access.securityManagerMethodNotSupported("checkExec");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkLink(final String lib) {
        throw access.securityManagerMethodNotSupported("checkLink");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkRead(final FileDescriptor fd) {
        throw access.securityManagerMethodNotSupported("checkRead");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkRead(final String file) {
        throw access.securityManagerMethodNotSupported("checkRead");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkRead(final String file, final Object context) {
        throw access.securityManagerMethodNotSupported("checkRead");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkWrite(final FileDescriptor fd) {
        throw access.securityManagerMethodNotSupported("checkWrite");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkWrite(final String file) {
        throw access.securityManagerMethodNotSupported("checkWrite");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkDelete(final String file) {
        throw access.securityManagerMethodNotSupported("checkDelete");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkConnect(final String host, final int port) {
        throw access.securityManagerMethodNotSupported("checkConnect");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkConnect(final String host, final int port, final Object context) {
        throw access.securityManagerMethodNotSupported("checkConnect");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkListen(final int port) {
        throw access.securityManagerMethodNotSupported("checkListen");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkAccept(final String host, final int port) {
        throw access.securityManagerMethodNotSupported("checkAccept");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkMulticast(final InetAddress maddr) {
        throw access.securityManagerMethodNotSupported("checkMulticast");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method is a no-op.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    @SuppressWarnings("deprecation")
    public void checkMulticast(final InetAddress maddr, final byte ttl) {
        // No-op on Java 25+ - SecurityManager enforcement is disabled by the JVM
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkPropertiesAccess() {
        throw access.securityManagerMethodNotSupported("checkPropertiesAccess");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkPropertyAccess(final String key) {
        throw access.securityManagerMethodNotSupported("checkPropertyAccess");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkPrintJobAccess() {
        throw access.securityManagerMethodNotSupported("checkPrintJobAccess");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkPackageAccess(final String pkg) {
        throw access.securityManagerMethodNotSupported("checkPackageAccess");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkPackageDefinition(final String pkg) {
        throw access.securityManagerMethodNotSupported("checkPackageDefinition");
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkSetFactory() {
        throw access.securityManagerMethodNotSupported("checkSetFactory");
    }


    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method is a no-op.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    @SuppressWarnings("deprecation")
    public void checkMemberAccess(final Class<?> clazz, final int which) {
        // No-op on Java 25+ - SecurityManager enforcement is disabled by the JVM
    }

    /**
     * @deprecated SecurityManager enforcement is disabled on Java 25+. This method throws UnsupportedOperationException.
     */
    @Deprecated(since = "2.8.5", forRemoval = true)
    public void checkSecurityAccess(final String target) {
        throw access.securityManagerMethodNotSupported("checkSecurityAccess");
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param action the action to perform
     * @param <T> the action return type
     * @return the return value of the action
     */
    public static <T> T doChecked(PrivilegedAction<T> action) {
        return action.run();
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param action the action to perform
     * @param <T> the action return type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T> T doChecked(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        try {
            return action.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param action the action to perform
     * @param context the access control context to use (ignored on Java 25+)
     * @param <T> the action return type
     * @return the return value of the action
     */
    public static <T> T doChecked(PrivilegedAction<T> action, AccessControlContext context) {
        return action.run();
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param action the action to perform
     * @param context the access control context to use (ignored on Java 25+)
     * @param <T> the action return type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T> T doChecked(PrivilegedExceptionAction<T> action, AccessControlContext context) throws PrivilegedActionException {
        try {
            return action.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     */
    public static <T, P> T doChecked(P parameter, ParametricPrivilegedAction<T, P> action) {
        return action.run(parameter);
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T, P> T doChecked(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        try {
            return action.run(parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param context the access control context to use (ignored on Java 25+)
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     */
    public static <T, P> T doChecked(P parameter, ParametricPrivilegedAction<T, P> action, AccessControlContext context) {
        return action.run(parameter);
    }

    /**
     * Perform an action with permission checking enabled.  If permission checking is already enabled, the action is
     * simply run.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param context the access control context to use (ignored on Java 25+)
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T, P> T doChecked(P parameter, ParametricPrivilegedExceptionAction<T, P> action, AccessControlContext context) throws PrivilegedActionException {
        try {
            return action.run(parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The immediate caller must have the {@code doUnchecked} runtime permission.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param action the action to perform
     * @param <T> the action return type
     * @return the return value of the action
     */
    public static <T> T doUnchecked(PrivilegedAction<T> action) {
        return action.run();
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The caller must have the {@code doUnchecked} runtime permission.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param action the action to perform
     * @param <T> the action return type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T> T doUnchecked(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        try {
            return action.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The immediate caller must have the {@code doUnchecked} runtime permission.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param action the action to perform
     * @param context the access control context to use (ignored on Java 25+)
     * @param <T> the action return type
     * @return the return value of the action
     */
    public static <T> T doUnchecked(PrivilegedAction<T> action, AccessControlContext context) {
        return action.run();
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The caller must have the {@code doUnchecked} runtime permission.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param action the action to perform
     * @param context the access control context to use (ignored on Java 25+)
     * @param <T> the action return type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T> T doUnchecked(PrivilegedExceptionAction<T> action, AccessControlContext context) throws PrivilegedActionException {
        try {
            return action.run();
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The immediate caller must have the {@code doUnchecked} runtime permission.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     */
    public static <T, P> T doUnchecked(P parameter, ParametricPrivilegedAction<T, P> action) {
        return action.run(parameter);
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The caller must have the {@code doUnchecked} runtime permission.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T, P> T doUnchecked(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        try {
            return action.run(parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The immediate caller must have the {@code doUnchecked} runtime permission.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param context the access control context to use (ignored on Java 25+)
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     */
    public static <T, P> T doUnchecked(P parameter, ParametricPrivilegedAction<T, P> action, AccessControlContext context) {
        return action.run(parameter);
    }

    /**
     * Perform an action with permission checking disabled.  If permission checking is already disabled, the action is
     * simply run.  The caller must have the {@code doUnchecked} runtime permission.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to perform
     * @param context the access control context to use (ignored on Java 25+)
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the return value of the action
     * @throws PrivilegedActionException if the action threw an exception
     */
    public static <T, P> T doUnchecked(P parameter, ParametricPrivilegedExceptionAction<T, P> action, AccessControlContext context) throws PrivilegedActionException {
        try {
            return action.run(parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }



    /**
     * Get a property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly calls System.getProperty() as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param name the property name
     * @param def the default value if the property is not found
     * @return the property value, or the default value
     */
    public static String getPropertyPrivileged(String name, String def) {
        return getProperty(name, def);
    }

    private static <T> T def(T test, T def) {
        return test == null ? def : test;
    }

    /**
     * Get an environmental property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly calls System.getenv() as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param name the property name
     * @param def the default value if the property is not found
     * @return the property value, or the default value
     */
    public static String getEnvPropertyPrivileged(String name, String def) {
        return def(getenv(name), def);
    }

    /**
     * Set a property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly calls System.setProperty() as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param name the property name
     * @param value the value ot set
     * @return the previous property value, or {@code null} if there was none
     */
    public static String setPropertyPrivileged(String name, String value) {
        return setProperty(name, value);
    }

    /**
     * Clear a property, doing a faster permission check that skips having to execute a privileged action frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly calls System.clearProperty() as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param name the property name
     * @return the previous property value, or {@code null} if there was none
     */
    public static String clearPropertyPrivileged(String name) {
        return clearProperty(name);
    }

    /**
     * Get the current thread's context class loader, doing a faster permission check that skips having to execute a
     * privileged action frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly calls Thread.currentThread().getContextClassLoader() as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @return the context class loader
     */
    public static ClassLoader getCurrentContextClassLoaderPrivileged() {
        return currentThread().getContextClassLoader();
    }

    /**
     * Set the current thread's context class loader, doing a faster permission check that skips having to execute a
     * privileged action frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly sets the context class loader as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param newClassLoader the new class loader to set
     * @return the previously set context class loader
     */
    public static ClassLoader setCurrentContextClassLoaderPrivileged(ClassLoader newClassLoader) {
        final Thread thread = currentThread();
        try {
            return thread.getContextClassLoader();
        } finally {
            thread.setContextClassLoader(newClassLoader);
        }
    }

    /**
     * Set the current thread's context class loader, doing a faster permission check that skips having to execute a
     * privileged action frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly sets the context class loader as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param clazz the class whose class loader is the new class loader to set
     * @return the previously set context class loader
     */
    public static ClassLoader setCurrentContextClassLoaderPrivileged(final Class<?> clazz) {
        final Thread thread = currentThread();
        try {
            return thread.getContextClassLoader();
        } finally {
            thread.setContextClassLoader(clazz.getClassLoader());
        }
    }

    /**
     * Get the system properties map, doing a faster permission check that skips having to execute a privileged action
     * frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly calls System.getProperties() as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @return the system property map
     */
    public static Properties getSystemPropertiesPrivileged() {
        return getProperties();
    }

    /**
     * Get the system environment map, doing a faster permission check that skips having to execute a privileged action
     * frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly calls System.getenv() as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @return the system environment map
     */
    public static Map<String, String> getSystemEnvironmentPrivileged() {
        return getenv();
    }

    /**
     * Get the class loader for a class, doing a faster permission check that skips having to execute a privileged action
     * frame.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this directly calls Class.getClassLoader() as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param clazz the class to check
     * @return the class loader
     */
    public static ClassLoader getClassLoaderPrivileged(Class<?> clazz) {
        return clazz.getClassLoader();
    }



    /**
     * Execute a parametric privileged action with the given parameter in a privileged context.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param parameter the parameter to send in to the action
     * @param action the action to execute
     * @param <T> the action result type
     * @param <P> the parameter type
     * @return the action result
     */
    public static <T, P> T doPrivilegedWithParameter(P parameter, ParametricPrivilegedAction<T, P> action) {
        return action.run(parameter);
    }

    /**
     * Execute a parametric privileged action with the given parameter in a privileged context.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM.</p>
     *
     * @param parameter the parameter to send in to the action
     * @param action the action to execute
     * @param <T> the action result type
     * @param <P> the parameter type
     * @return the action result
     */
    public static <T, P> T doPrivilegedWithParameter(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        try {
            return action.run(parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Execute a parametric privileged action with the given parameter with the given context.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param parameter the parameter to send in to the action
     * @param action the action to execute
     * @param accessControlContext the context to use (ignored on Java 25+)
     * @param <T> the action result type
     * @param <P> the parameter type
     * @return the action result
     */
    public static <T, P> T doPrivilegedWithParameter(P parameter, ParametricPrivilegedAction<T, P> action, AccessControlContext accessControlContext) {
        return action.run(parameter);
    }

    /**
     * Execute a parametric privileged action with the given parameter with the given context.
     *
     * <p><strong>Java 25+ Note:</strong> On Java 25+, this simply runs the action directly as
     * SecurityManager enforcement is disabled by the JVM. The context parameter is ignored.</p>
     *
     * @param parameter the parameter to send in to the action
     * @param action the action to execute
     * @param accessControlContext the context to use (ignored on Java 25+)
     * @param <T> the action result type
     * @param <P> the parameter type
     * @return the action result
     */
    public static <T, P> T doPrivilegedWithParameter(P parameter, ParametricPrivilegedExceptionAction<T, P> action, AccessControlContext accessControlContext) throws PrivilegedActionException {
        try {
            return action.run(parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

}
