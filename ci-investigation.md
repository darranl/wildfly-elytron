# CI Investigation: OIDC Back-Channel Logout Tests

## Summary

This document records the investigation of CI failures in OIDC back-channel logout tests, specifically [`BackChannelLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java) and [`BackChannelLogoutAbsoluteUrlTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutAbsoluteUrlTest.java). The investigation has evolved from a single test failure to understanding test interaction issues when running the full OIDC test suite.

## Original Failure

CI reported a timeout in [`testBackChannelLogout()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:58):

- `java.net.SocketTimeoutException: Read timed out`
- failure occurs while HtmlUnit is executing [`webClient.getPage(...)`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:77)

Observed stack trace from CI artifacts points to the client waiting for an HTTP response rather than failing an assertion.

## Working Assumptions

### Assumption 1: This is more likely a test/environment issue than a core implementation issue

Current evidence suggests the timeout is caused by the test topology and networking assumptions in CI, not by a fundamental error in Elytron logout handling.

Why:
- The secured mock application responds successfully to the RP-initiated logout endpoint.
- The stall appears to happen after the redirect to Keycloak’s end-session endpoint.
- The configured backchannel logout URL uses an address derived from [`InetAddress.getLocalHost().getHostAddress()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:52), which is brittle in CI/container environments.

### Assumption 2: Keycloak is likely unable to reach the configured backchannel logout URL from inside the container

The logged callback URL from CI was:

- `http://10.1.0.15:5002/clientApp/logout/callback`

This strongly suggests the test is depending on a host address that may not be reachable from the Keycloak container.

### Assumption 3: The timeout occurs after the mock app has already done its part

The artifact logs show that the mock application processed:

- [`GET /clientApp/logout`](results/http/oidc/target/surefire-reports/org.wildfly.security.http.oidc.BackChannelLogoutTest-output.txt:177)

and responded with:

- `HTTP/1.1 302 Redirection`

So the initial application-side logout request completed. The subsequent request chain appears to stall elsewhere.

## Relevant Code Areas

### Test under investigation

- [`BackChannelLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java)
- [`AbstractLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/AbstractLogoutTest.java)
- [`OidcBaseTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/OidcBaseTest.java)
- [`KeycloakContainer`](http/oidc/src/test/java/org/wildfly/security/http/oidc/KeycloakContainer.java)

### Suspect code path

The current backchannel logout URL is built in [`doConfigureClient()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:38) using [`rewriteHost()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:50), which currently replaces `localhost` with the result of [`InetAddress.getLocalHost().getHostAddress()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:52).

This is the most suspicious part of the test setup.

## Investigation Performed

### 1. Identified where the timeout occurs

The original failure showed HtmlUnit timing out while executing the final logout navigation.

This pointed away from a simple local assertion failure and toward an HTTP call chain that never completed.

### 2. Inspected the local mock app dispatch path

[`ElytronDispatcher.dispatch()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/AbstractLogoutTest.java:163) catches exceptions and returns a response, which makes it less likely that the mock app silently hung due to an unhandled error.

This increased suspicion that the blocking point was external to the mock dispatcher.

### 3. Reduced CI scope to iterate faster

The GitHub Actions workflow was updated in [`.github/workflows/pr-ci.yaml`](.github/workflows/pr-ci.yaml) so that CI now:

- runs only on Ubuntu
- runs only Java 17 and 21
- builds all modules with `mvn install -DskipTests` to ensure dependencies are available
- runs only the tests in the http/oidc module in a separate step
- uploads failure artifacts
- always saves the Maven cache

These changes allow testing all OIDC tests together to identify any test interaction issues while avoiding the overhead of running tests in unrelated modules.

### 4. Added backchannel logout URL logging

Logging was added to [`BackChannelLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java) so the exact configured callback URL is visible in CI output.

This confirmed the callback URL as:

- `http://10.1.0.15:5002/clientApp/logout/callback`

### 5. Added Keycloak container log emission hook

A helper was added to [`KeycloakContainer.logContainerOutput()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/KeycloakContainer.java:80) and it is invoked from [`OidcBaseTest.generalCleanup()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/OidcBaseTest.java:117).

However, the current uploaded artifacts do not yet show the expected Keycloak logs, so either:
- the logs are not being captured in the uploaded files, or
- they are emitted to a stream not included in the collected artifacts.

## Findings From Uploaded CI Artifacts

### Confirmed observations

From the uploaded surefire output:

1. The backchannel URL configured by the test is:

   - [`Configured backchannel logout URL: http://10.1.0.15:5002/clientApp/logout/callback`](results/http/oidc/target/surefire-reports/org.wildfly.security.http.oidc.BackChannelLogoutTest-output.txt:152)

2. The authenticated application request succeeds.

3. The RP-initiated logout endpoint is reached:

   - [`Evaluating request URI: [http://localhost:5002/clientApp/logout]`](results/http/oidc/target/surefire-reports/org.wildfly.security.http.oidc.BackChannelLogoutTest-output.txt:158)

4. Elytron sends the redirect to Keycloak’s end-session endpoint:

   - [`Sending redirect to the end_session_endpoint ...`](results/http/oidc/target/surefire-reports/org.wildfly.security.http.oidc.BackChannelLogoutTest-output.txt:176)

5. The mock application returns its redirect response:

   - [`MockWebServer[5002] received request: GET /clientApp/logout HTTP/1.1 and responded: HTTP/1.1 302 Redirection`](results/http/oidc/target/surefire-reports/org.wildfly.security.http.oidc.BackChannelLogoutTest-output.txt:177)

6. After that, the client waits and eventually times out:

   - [`java.net.SocketTimeoutException: Read timed out`](results/http/oidc/target/surefire-reports/org.wildfly.security.http.oidc.BackChannelLogoutTest.txt:6)

### Interpretation

This is consistent with the following sequence:

1. HtmlUnit requests the logout endpoint on the mock app.
2. Elytron correctly issues a redirect to Keycloak’s logout endpoint.
3. HtmlUnit follows that redirect.
4. Keycloak attempts backchannel logout to the configured callback URL.
5. That callback URL is not reachable from the Keycloak container in CI.
6. Keycloak does not complete the response in a timely way.
7. HtmlUnit times out waiting for the logout response chain to complete.

## Why This Looks Like a Test Issue

The test had two issues:

1. **Host Reachability**: The test assumed that a host IP resolved from [`InetAddress.getLocalHost().getHostAddress()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:52) is a stable and container-reachable callback target. That assumption is often false in GitHub Actions and other containerized CI environments.

2. **Timeout Configuration**: The test did not configure an explicit timeout for the HtmlUnit WebClient. The backchannel logout flow requires:
   - Browser initiates logout request to the application
   - Application redirects to Keycloak's end-session endpoint
   - Keycloak makes a **separate HTTP POST** to the backchannel callback URL
   - Only after the backchannel callback completes does Keycloak respond to the browser

   This means `webClient.getPage()` blocks waiting for Keycloak's response, which in turn waits for the backchannel callback to complete. On Java 17, the default HtmlUnit timeout appears to be insufficient for this flow in CI environments.

The issues therefore appear to be in how the test configures networking and timeouts, rather than in the logout implementation itself.

## Proposed Fix Direction

### Primary fix to try next

Replace the current host rewrite logic in [`BackChannelLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java) with a host that is explicitly routable from the Keycloak container.

Candidate approach:
- use a Testcontainers-supported host-access hostname such as `host.testcontainers.internal`
- ensure the container is configured to access the host if required by the Testcontainers version/setup

### Why this is preferred

- It directly addresses the most likely failing assumption.
- It keeps the test aligned with the intended scenario.
- It avoids adding more logging before trying the simplest likely fix.

## Possible Implementation Approaches

### Option A: Replace `localhost` with `host.testcontainers.internal`

In [`rewriteHost()`](http://http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:50), replace `localhost` with `host.testcontainers.internal` rather than using [`InetAddress.getLocalHost().getHostAddress()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:52).

Potentially also ensure the Keycloak container is started with host access enabled.

### Option B: Make the callback host configurable via system property

Introduce a test-only system property for the callback host. For example:
- default locally to current behavior or `localhost`
- override in CI to a container-reachable value

This would allow experimentation without repeatedly rewriting the test logic.

### Option C: Use a Testcontainers host helper centrally in the base test setup

If the project already has or can adopt a standard host-access pattern, apply it in [`AbstractLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/AbstractLogoutTest.java) or [`KeycloakContainer`](http/oidc/src/test/java/org/wildfly/security/http/oidc/KeycloakContainer.java) rather than only in this test.

This is cleaner if more tests will need the same pattern.

## Additional Logging: Needed or Not?

### Short answer

More logging could help, but it is not strictly required before trying the test fix.

### Most useful additional logging if needed

If the first fix attempt fails, then add one of the following:

1. Capture Keycloak logs into a dedicated file under a `target` directory so they are guaranteed to be uploaded.
2. Log whether the callback endpoint [`/clientApp/logout/callback`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:47) is ever actually hit by the mock app.
3. Log container host-access configuration at startup.

At present, the strongest missing signal is whether Keycloak ever attempted the callback and what exact network failure it saw.

## Plan of Action

### Step 1 ✅ COMPLETED
Change the test to stop using [`InetAddress.getLocalHost().getHostAddress()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:52) for the backchannel callback host.

**Implementation:** Modified [`rewriteHost()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:55) to replace `localhost` with `host.testcontainers.internal` instead of using `InetAddress.getLocalHost().getHostAddress()`. Removed unused imports for `InetAddress` and `UnknownHostException`.

### Step 2 ✅ COMPLETED
Use a host value intended to be reachable from inside the Keycloak container, most likely `host.testcontainers.internal`.

**Implementation:** The backchannel logout URL will now use `host.testcontainers.internal` as the host, which is the standard Testcontainers hostname for accessing the host machine from within a container.

### Step 3 ✅ COMPLETED
If needed, update [`KeycloakContainer`](http/oidc/src/test/java/org/wildfly/security/http/oidc/KeycloakContainer.java) to explicitly allow host access for the container.

**Implementation:** Added `withAccessToHost(true)` to the [`configure()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/KeycloakContainer.java:60) method to enable the Keycloak container to reach back to the host machine.

### Step 4 ✅ COMPLETED
Re-run the narrowed CI workflow and inspect:
- whether the callback URL changed as expected
- whether the timeout disappears
- whether the mock app receives the backchannel callback request

**Status:** Test now passes when run in isolation. The host reachability and timeout fixes resolved the issue for single test execution.

### Step 5 ✅ COMPLETED - Applied Same Fixes to BackChannelLogoutAbsoluteUrlTest
**Finding:** [`BackChannelLogoutAbsoluteUrlTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutAbsoluteUrlTest.java) had the identical issues as [`BackChannelLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java):
- Used `InetAddress.getLocalHost().getHostAddress()` for backchannel callback URL
- No explicit timeout for the logout request

**Implementation:** Applied the same fixes:
1. Modified [`rewriteHost()`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutAbsoluteUrlTest.java:49) to use `host.testcontainers.internal`
2. Added 60-second timeout before the logout request at line 78
3. Removed unused imports
4. Updated CI workflow to test this specific test

### Step 6 ✅ COMPLETED
Updated CI workflow to run all OIDC tests together rather than individual tests. This will help identify if there are test interaction issues when multiple OIDC tests run in sequence.

**Implementation:**
- First step: Build all modules with `mvn install -DskipTests` to ensure all dependencies are available in the local Maven repository
- Second step: Run `mvn test --file http/oidc/pom.xml` to execute all OIDC tests

### Step 7 ⏳ IN PROGRESS
Re-run CI with all OIDC tests to:
1. Verify both [`BackChannelLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java) and [`BackChannelLogoutAbsoluteUrlTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutAbsoluteUrlTest.java) pass with the fixes
2. Identify any test interaction issues when running the full OIDC test suite

### Step 8 ⏸️ PENDING
If tests fail when run together, investigate test interaction issues:
- Check for proper test cleanup between tests
- Verify Keycloak container lifecycle management
- Look for resource leaks (ports, connections, threads)
- Consider test execution order dependencies

## Suggested Next Conversation Reset Point

When resuming work after clearing context, start with:

- review [`ci-investigation.md`](ci-investigation.md)
- implement Step 1 through Step 3 from the plan
- re-run the narrowed CI
- inspect whether the callback request reaches the mock app

## Files Changed So Far

### Initial diagnostic changes
- [`.github/workflows/pr-ci.yaml`](.github/workflows/pr-ci.yaml) - narrowed CI scope for faster iteration
- [`BackChannelLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java) - added logging for backchannel URL
- [`KeycloakContainer`](http/oidc/src/test/java/org/wildfly/security/http/oidc/KeycloakContainer.java) - added log emission hook
- [`OidcBaseTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/OidcBaseTest.java) - invoked log emission in cleanup

### Current iteration (host routing and timeout fixes)
- [`BackChannelLogoutTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java):
  - Replaced `InetAddress.getLocalHost().getHostAddress()` with `host.testcontainers.internal`
  - Added explicit 60-second timeout for the logout request to allow time for backchannel callback completion
- [`BackChannelLogoutAbsoluteUrlTest`](http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutAbsoluteUrlTest.java):
  - Replaced `InetAddress.getLocalHost().getHostAddress()` with `host.testcontainers.internal`
  - Added explicit 60-second timeout for the logout request to allow time for backchannel callback completion
  - Removed unused imports for `InetAddress` and `UnknownHostException`
- [`KeycloakContainer`](http/oidc/src/test/java/org/wildfly/security/http/oidc/KeycloakContainer.java) - enabled host access with `withAccessToHost(true)`
- [`.github/workflows/pr-ci.yaml`](.github/workflows/pr-ci.yaml) - updated to skip all tests during build and run all http/oidc module tests together

## Root Cause Analysis

### Java 17 vs Java 21 Behavior

The test passed on Java 21 but hung on Java 17, suggesting a difference in:
- HtmlUnit's default timeout behavior between Java versions
- Thread pool management in the underlying HTTP client
- Network stack timing characteristics

### The Race Condition

The backchannel logout creates a potential race condition:
1. Main test thread calls `webClient.getPage()` which blocks
2. Keycloak needs to make a backchannel POST to the mock server
3. The MockWebServer dispatcher must handle this POST on a separate thread
4. Only after the POST completes can Keycloak respond to the blocked `webClient.getPage()` call

Without an explicit timeout, HtmlUnit may use a default timeout that's too short for this multi-step flow, especially in slower CI environments or with different Java versions.

### The Solution

Two changes were required:
1. **Fix host reachability**: Use `host.testcontainers.internal` with `withAccessToHost(true)` so Keycloak can reach the mock server
2. **Increase timeout**: Set `webClient.getOptions().setTimeout(60000)` to allow sufficient time for the backchannel callback to complete

## Notes

One malformed link should be corrected in future edits if this file is updated:
- the [`rewriteHost()`](http://http/oidc/src/test/java/org/wildfly/security/http/oidc/BackChannelLogoutTest.java:50) reference in "Option A" should point to the local file path without the duplicated protocol prefix.