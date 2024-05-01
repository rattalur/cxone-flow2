# CxOne Flow

If you are familiar with [CxFlow](https://github.com/checkmarx-ltd/cx-flow) for Checkmarx SAST, the role of CxOne Flow will be familiar.  

If not, CxOne Flow is a scan orchestrator that executes multiple source code analysis scans.  

## CxOneFlow vs CxFlow

CxOneFlow is not intended to ever reach feature parity with CxFlow.  Many CxFlow features will not apply to Checkmarx One scanning.  CxOneFlow currently orchestrates scans via webhook events for push and pull-requests involving protected branches.  CxOneFlow
itself does not create results in feedback applications.

The issue tracker feedback applications implemented by Checkmarx One will execute after
a scan if configured.  This will not generally create or update a pull-request comment
but will manage the issue lifecycle in an issue tracker.


# Quickstart and Documentation

Please refer to the [Releases](https://github.com/checkmarx-ts/cxone-flow/releases) where you will find a PDF manual that will explain configuration steps for a quick evaluation.


# Current State

This repository is currently visible internally to Checkmarx only while testing is performed. This section will explain what is currently needed
before release.

## Execution Features

Currently, only the following features work:

* BitBucket Data Center as an SCM
* Scans are invoked by Push events targetting protected branches.



## BitBucket Data Center Test Environment

A docker image of [Bitbucket Data Cener](https://hub.docker.com/r/atlassian/bitbucket) can be created for testing purposes.

It is suggested that you make a volume so that the configuration persists across runs of the BBDC image:

`docker volume create --name bb`

You can then execute BBDC:

`docker run --rm -it -v bb:/var/atlassian/application-data/bitbucket --name="bbdc" -p 7990:7990 -p 7999:7999 atlassian/bitbucket:latest`

It is suggested you create an entry in `hosts` to resolve a realistic domain name to `127.0.0.1` for the Bitbucket Server.  This
will make it easier to simulate a real SCM instance.

A temporary license can be obtained when starting the server.  It is recommended to use a [temporary email address](https://temp-mail.org/en/) and
interact with Bitbucket via an incognito browser.  An incognito browser will prevent interference with credentials used to log into live Atlassian
products (like those used internally by Checkmarx) when you have logins cached in your browser.

The current testing has been performed on BBDC 8.19.2.  What is needed is to regress at least one version of BBDC before 8.19 to see if it is also
compatible.

## Documentation

If you read the documentation and it is not clear, please do the research needed to understand what would make it clear so the documentation can be fixed.

The manuals are written in Latex.  Updating the documentation can be done two ways:

* The manual explains how to set up your development environment to support Latex authoring.  If you want to go this route and update the manual, please cut a branch, update
the `.tex` files with your updates, make sure you are on the title page as a contributor, and open a pull request when your updates are complete.
* You can alternately file a GitHub issue explaining the problem and what needs to change and the documentation will be updated when possible.


## Testing Needs

A single instance with a single SCM organization has been tested.  Some scenarios that have not been tested:

* Deploying with the CxOneFlow endpoint using SSL.
* Configuration for multiple orgs emitting webhooks to the CxOneFlow endpoint.
* Configuration for multiple SCM instances each having one or more orgs emitting webhooks to the CxOneFlow endpoint.
* Multiple concurrent webhook payload deliveries invoking the CxOneFlow workflow.

There will be bugs.

