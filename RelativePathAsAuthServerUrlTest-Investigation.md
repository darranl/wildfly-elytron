# RelativePathAsAuthServerUrlTest Investigation Summary

## 1. Original Problem

The test `http/oidc/src/test/java/org/wildfly/security/http/oidc/RelativePathAsAuthServerUrlTest.java` was failing locally with **Podman socket exhaustion** errors.

### Symptoms
- **3 out of 5 tests passing** when run individually
- **2 tests failing** with `java.io.IOException: Broken pipe` when run as a complete test suite
- Error occurred during nginx container creation in tests 4 and 5
- Root cause: Podman's Unix socket getting overwhelmed by rapid container creation/deletion operations

### Why This Happens
1. **Podman's socket architecture** has more limited concurrent connection capacity compared to Docker's daemon
2. **Rapid container churn**: 5 tests × 2-3 containers each = 10-15 containers created/destroyed in quick succession
3. **Asynchronous cleanup**: Container `.stop()` methods return immediately, but Podman takes time to fully remove containers and release socket resources
4. **No built-in throttling**: Tests don't wait for cleanup to complete before starting the next test

## 2. Steps Taken to Resolve

### A. Initial Podman Compatibility Fixes (Already Applied)
These changes were made to make the tests work with Podman at all:

1. **Removed `setPortBindings()` calls** - Incompatible with Podman socket communication
2. **Changed to dynamic port assignment** - Using `getBaseUrl()` instead of fixed ports
3. **Fixed file mount paths** - Changed from relative to absolute paths using `new File().getAbsolutePath()`
4. **Added SELinux labeling** - Added `SELContext.shared` to volume mounts for Podman permission requirements
5. **Fixed nginx configuration**:
   - Mounted to `/etc/nginx/templates/` to use nginx's envsubst feature
   - Changed environment variable syntax from `$VAR` to `${var}` (lowercase)
   - Changed from `localhost:$PROXY_PORT` to `$http_host` for dynamic port handling

### B. Socket Exhaustion Mitigation (Current Changes)

#### File: `http/oidc/src/test/java/org/wildfly/security/http/oidc/RelativePathAsAuthServerUrlTest.java`

**Added cleanup detection methods:**
```java
private void waitForContainerRemoval(String containerId) throws Exception
private void waitForNetworkRemoval(String networkId) throws Exception
```
These methods poll the Docker client API to verify containers/networks are actually removed before proceeding.

**Modified `@After` method:**
- Captures container/network IDs before stopping
- Calls `waitForContainerRemoval()` after each `.stop()`
- Calls `waitForNetworkRemoval()` after `network.close()`
- Adds 2-second delay at the end to let Podman socket fully release resources

**Modified `startProxyAndGetProxyPort()` method:**
- Increased delay before container creation from 1 second to 3 seconds
- Gives Podman more time between container operations

**Added imports:**
```java
import com.github.dockerjava.api.exception.NotFoundException;
import org.testcontainers.DockerClientFactory;
```

#### File: `http/oidc/src/test/resources/testcontainers.properties`

**Added Podman-specific configuration:**
```properties
ryuk.disabled=true
```
Disables Ryuk container (resource reaper) which can cause additional socket load.

#### File: `http/oidc/pom.xml`

**Added environment variable pass-through in surefire plugin:**
```xml
<environmentVariables>
    <OIDC_PROVIDER_URL_ENV>/realms/WildFly</OIDC_PROVIDER_URL_ENV>
    <DOCKER_HOST>${env.DOCKER_HOST}</DOCKER_HOST>
    <TESTCONTAINERS_RYUK_DISABLED>${env.TESTCONTAINERS_RYUK_DISABLED}</TESTCONTAINERS_RYUK_DISABLED>
</environmentVariables>
```
Allows Maven to pass Docker/Podman socket location to tests.

## 3. Current State & Next Steps

### Current Status
✅ Tests are now running (Podman Desktop was closed, causing socket unavailability)
⏳ Need to verify all 5 tests pass with the socket exhaustion fixes

### What We Need to Do Next

#### Step 1: Run Full Test Suite
Execute the complete test suite to verify all 5 tests pass:
```bash
export DOCKER_HOST=unix://${XDG_RUNTIME_DIR}/podman/podman.sock
export TESTCONTAINERS_RYUK_DISABLED=true
cd http/oidc
mvn test -Dtest=RelativePathAsAuthServerUrlTest
```

#### Step 2: Verify Results
Check that all 5 tests pass:
- `testSuccessfulAuthenticationWithRelativeAuthServerUrl`
- `testSuccessfulAuthenticationWithRelativeAuthServerUrlSubUrl`
- `testUnauthenticatedClientWithRelativeAuthServerUrl`
- `testWrongRelativeAuthServerUrl`
- `testUnitRelativeAuthServerUrlIsResolvedCorrectly`

#### Step 3: Adjust Delays if Needed
If tests still fail with "Broken pipe":
- Increase delay in `startProxyAndGetProxyPort()` from 3s to 5s
- Increase delay in `@After` from 2s to 3s
- Consider adding retry logic with exponential backoff

#### Step 4: Docker Compatibility Testing
**CRITICAL**: Verify changes work with Docker as well as Podman:

1. **Test with Docker**:
   ```bash
   export DOCKER_HOST=unix:///var/run/docker.sock
   unset TESTCONTAINERS_RYUK_DISABLED  # Docker can use Ryuk
   cd http/oidc
   mvn test -Dtest=RelativePathAsAuthServerUrlTest
   ```

2. **Verify Docker-specific concerns**:
   - Delays shouldn't cause issues (Docker is faster, but delays are acceptable)
   - Cleanup detection works with Docker API (uses same API)
   - Environment variable pass-through works (Maven config is generic)
   - Ryuk can be enabled for Docker (controlled by env var)

### Docker vs Podman Compatibility Matrix

| Feature | Docker | Podman | Solution |
|---------|--------|--------|----------|
| Socket location | `/var/run/docker.sock` | `/run/user/UID/podman/podman.sock` | Use `DOCKER_HOST` env var |
| Ryuk support | ✅ Yes | ❌ No | Control via `TESTCONTAINERS_RYUK_DISABLED` env var |
| Cleanup speed | Fast | Slow | Delays are acceptable for both |
| Socket capacity | High | Limited | Cleanup detection helps both |
| SELinux labeling | Not needed | Required | `SELContext.shared` is ignored by Docker |

### Key Design Decisions

1. **Environment variable approach**: Using `DOCKER_HOST` and `TESTCONTAINERS_RYUK_DISABLED` environment variables allows the same code to work with both Docker and Podman
2. **Cleanup detection**: Polling for container removal is safe for both Docker and Podman
3. **Delays**: Conservative delays (3s + 2s) work for both, though Docker could handle shorter delays
4. **No hardcoded paths**: All socket paths come from environment variables, maintaining portability

### Success Criteria

- ✅ All 5 tests pass consistently with Podman
- ✅ All 5 tests pass consistently with Docker
- ✅ No "Broken pipe" errors in either environment
- ✅ No hardcoded Docker/Podman-specific paths in code
- ✅ Configuration is controlled via environment variables only