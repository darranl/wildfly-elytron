WildFly Elytron
===============

[WildFly Elytron](https://wildfly-security.github.io/wildfly-elytron/) is a new WildFly sub-project which is completely replacing the combination of PicketBox and JAAS as the WildFly client and  server security mechanism.
 
An "elytron" (ĕl´·ĭ·trŏn, plural "elytra") is the hard, protective casing over a wing of certain flying insects (e.g. beetles).

Building From Source
--------------------

```console
$ git clone git@github.com:wildfly-security/wildfly-elytron.git
```

Setup the JBoss Maven Repository
--------------------------------

To use dependencies from JBoss.org, you need to add the JBoss Maven Repositories to your Maven settings.xml. For details see [Maven Getting Started - Users](https://developer.jboss.org/docs/DOC-15169)

Build with Maven
----------------

The command below builds the project and runs the embedded suite.

```console
$ mvn clean install
```

### Multi-Version Testing

WildFly Elytron supports testing across multiple Java versions (17, 21, 25) using Maven Toolchains.

**Quick Setup:**

1. Copy the toolchains template:
   ```console
   $ cp toolchains.xml.template ~/.m2/toolchains.xml
   ```

2. Edit `~/.m2/toolchains.xml` and update JDK paths to match your installations

3. Verify configuration:
   ```console
   $ mvn toolchains:display-toolchains
   ```

**Recommended: Use SDKMAN for JDK Management**

Install SDKMAN and required JDKs:
```console
$ curl -s "https://get.sdkman.io" | bash
$ source "$HOME/.sdkman/bin/sdkman-init.sh"

# Install Temurin (Eclipse Adoptium)
$ sdk install java 17.0.13-tem
$ sdk install java 21.0.5-tem
$ sdk install java 25.0.0-tem

# Install Semeru (IBM OpenJ9)
$ sdk install java 17.0.13-sem
$ sdk install java 21.0.5-sem
$ sdk install java 25.0.0-sem

# Set Java 25 as default
$ sdk default java 25.0.0-tem
```

**Testing with Specific Java Versions:**

```console
# Test with Java 17
$ mvn test -Djdk.test.version=17

# Test with Java 21
$ mvn test -Djdk.test.version=21

# Test with Java 25
$ mvn test -Djdk.test.version=25

# Test with specific distribution (Semeru)
$ mvn test -Djdk.test.version=21 -Djdk.test.vendor=semeru
```

For more details, see `toolchains.xml.template`.

Issue Tracking
--------------

Bugs and features are tracked within the Elytron Jira project at https://issues.redhat.com/browse/ELY

Contributions
-------------

All new features and enhancements should be submitted to 2.x branch only.
Our [contribution guide](https://github.com/wildfly-security/wildfly-elytron/blob/2.x/CONTRIBUTING.md) will guide you through the steps for getting started on the WildFly Elytron project and will go through how to format and submit your first PR.
 
For more details, check out our [getting started guide](https://wildfly-security.github.io/wildfly-elytron/getting-started-for-developers/) for developers.

Example Feature Demos
---------------------

Our [elytron-examples](https://github.com/wildfly-security-incubator/elytron-examples) repository contains example demos of WildFly Elytron features.

Get Help
--------
There are a couple ways to get in touch with us.

Feel free to ask questions on the WildFly user [forum](https://groups.google.com/g/wildfly).  

The WildFly Elytron team also has an open chat room where you can listen in and ask questions. Join us on [Zulip chat](https://wildfly.zulipchat.com/#narrow/stream/173102-wildfly-elytron).
