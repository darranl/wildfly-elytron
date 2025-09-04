# Releasing WildFly Elytron

At this point in time the following branches are being maintained for the WildFly Elytron project:

 * 1.15.x
 * 2.2.x
 * 2.6.x
 * 2.x
 * 3.x

To release WildFly Elytron first checkout the project and ensure you are on the latest commit for the branch you are releasing with no local changes.

Prior to releasing you should ensure you have your own GPG signing key set up, published to a key server and listed on [wildfly.org](https://www.wildfly.org/contributors/pgp/).

## Prepare the release

Execute:

    mvn release:prepare

Enter the version being released:

    What is the release version for "WildFly Elytron Parent"? (wildfly-elytron-parent) 1.15.27.CR1: 1.15.27.Alpha1

The tag will default to the version:

    What is the SCM release tag or label for "WildFly Elytron Parent"? (wildfly-elytron-parent) 1.15.27.Alpha1:

Set the next version:

    What is the new development version for "WildFly Elytron Parent"? (wildfly-elytron-parent) 1.15.28.Alpha1-SNAPSHOT: 1.15.27.CR1-SNAPSHOT

The release commit can be checked with:

    git show ${TAG}

If everything is Ok perform the release which will deploy to Nexus.

## Perform the release

Execute:

    mvn release:perform -Pjboss-release

This will deploy the release to the `wildfly-staging` repository.

Wait for 10 minutes then visit the Validation task for the `wildfly-staging` repository in Nexus. If this task ran at least 10 minutes after the release was deployed check the latest results on the Settings tab and verify that at least one component was processed and that there were no errors. If the task has not run it can be manually kicked off using the Run button.

e.g.

> Processed 70 components.
> - no errors were found.
> - the deployment was a dry run (no actual publishing).

If others are also deploying at the same time this count could be higher, the important check is that the scan was at least 10 minutes after it was deployed, 1 or more components were scanned and no errors specific to WildFly Elytron are reported.

Nexus only scans components once if there are no issues so if you check these results after multiple scans the component count may be back to 0.

## Complete the release

If no issues are reported complete the release.

Move the component to the `wildfly-security` repository:

    git checkout ${TAG}
    mvn nxrm3:staging-move
    git checkout ${BRANCH}

Push the branch and tag to GitHub:

    git push upstream ${BRANCH}
    git push upstream ${TAG}

## Rollback the Release

If the release failed, revert the release.

Delete the component from Nexus:

    git checkout ${TAG}
    mvn nxrm3:staging-delete
    git checkout ${BRANCH}

Reset your local Git checkout:

    git reset --hard upstream/${BRANCH}
    git tag --delete ${TAG}

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

