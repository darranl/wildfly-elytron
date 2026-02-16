# Releasing WildFly Elytron

At this point in time the following branches are being maintained for the WildFly Elytron project:

 * 1.15.x (Java 11)
 * 2.2.x (Java 11)
 * 2.6.x (Java 11)
 * 2.x (Java 17)
 * 3.x (Java 17)

To release WildFly Elytron first checkout the project and ensure you are on the latest commit for the branch you are releasing with no local changes.

Prior to releasing you should ensure you have your own GPG signing key set up, published to a key server and listed on [wildfly.org](https://www.wildfly.org/contributors/pgp/).

Before performing a release you will need to set up a Sonatype access token with permission to push to the `org.wildfly.security` namespace as a server entry
in your settings.xml

    <server>
        <id>central</id>
        <username>XXX</username>
        <password>xxxxxxxxxxxxxxxxxxxxxx</password>
    </server>

## Prepare the release

Execute:

    mvn release:prepare

Enter the version being released:

    What is the release version for "WildFly Elytron Parent"? (wildfly-elytron-parent) 2.8.1.CR1: 2.8.1.Final

The tag will default to the version:

    What is the SCM release tag or label for "WildFly Elytron Parent"? (wildfly-elytron-parent) 2.8.1.Final:

Set the next version:

    What is the new development version for "WildFly Elytron Parent"? (wildfly-elytron-parent) 2.8.2.Final-SNAPSHOT: 2.8.2.CR1-SNAPSHOT

The release commit can be checked with:

    git show ${TAG}

If everything is Ok perform the release which will deploy to Maven Central.

## Perform the release

Execute:

    mvn release:perform

This will deploy the release directly to Maven central.

The end of the build process will indicate if there are any validation errors with the
proposed artifacts.

## Complete the release

If no issues are reported complete the release.

Log into [Maven Central: Publishing](https://central.sonatype.com/publishing), and
click `Publish` on the release.

The Maven Central interface will also indicate if there are errors and you will not
be able to click on `Publish` if any are present.

Push the branch and tag to GitHub:

    git push upstream ${BRANCH}
    git push upstream ${TAG}

## Rollback the Release

If the release failed, revert the release.

Log into [Maven Central: Publishing](https://central.sonatype.com/publishing), and
click `Drop` on the release.

Reset your local Git checkout:

    git reset --hard upstream/${BRANCH}
    git tag --delete ${TAG}

Correct any errors and try again.

# Update API check

Remember to update the API check which is done by japicmp maven plugin to a version you've just released.

The version is specified within the `wildfly-security/pom.xml` pom file.

# Forward Merging

After releasing one of the maintenance branches the branch must also be merged to the next branch under active maintenance, if there are intermediate branches not listed above they can be ignored.

The following example demonstrates merging from `1.15.x` to `2.2.x`:

    git checkout -b 2_2_x_sync -t upstream/2.2.x

Check the log from the 1.15.x branch and identify the last commit before the `[maven-release-plugin]` commits and merge it to this topic branch:

    git merge 64e0bd99c9edb8e4456905a8e104bf129bcaa38b -m "Sync from 1.15.x"

At this stage you may need to resolve any merge conflicts, be careful to not rebase - this should be committed as a merge commit.

Now we need to merge the release commits as well:

    git merge -s ours 1.15.x -m "Sync version commits from 1.15.x"

For this last command we use `-s ours` as we don't want git to actually apply these changes but we do want git to record that we have handled that part of merging.

This topic branch can now be submitted as a normal PR to kick off CI and merged once it passes. No review is required as this is merging previously approved changes unless you would like someone to verify especially if there were merge conflicts.

It is also work mentioning that the first merge can be performed at ant time if a maintenance branch contains merged changes which are required in a later branch. Provided we use merge commits and do not modify the SHAs git can track what has and has not been merged already.

