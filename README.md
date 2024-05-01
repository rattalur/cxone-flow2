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

