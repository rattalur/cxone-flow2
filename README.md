# CxOne Flow

If you are familiar with [CxFlow](https://github.com/checkmarx-ltd/cx-flow) for Checkmarx SAST,
the role of CxOne Flow will be familiar.  If not, CxOne Flow is a scan and feedback orchestrator
that executes code analysis scans and reports issues in an issue tracker or as pull-request
decorations.

## CxOneFlow vs CxFlow

CxOneFlow is not intended to ever reach feature parity with CxFlow.  Many CxFlow features will not apply
to Checkmarx One scanning.  CxOneFlow currently only orchestrates scans via webhook events for push and
pull-requests involving protected branches.

# Quickstart and Documentation

Please refer to the [Releases](https://github.com/checkmarx-ts/cxone-flow/releases) where you will find
a PDF manual.


# Developing

The development is performed on Ubuntu using Visual Studio Code.  This is not 
strictly required but any instructions for quick starting the development environment 
will be for using Ubuntu and VSCode. If you have different development tooling you'd like
to use, you'll need to adapt these instructions to fit your tooling.

## LaTeX

The documentation is written in LaTeX, so enabling VSCode to lint, compile, and preview
LaTeX requires some configuration.

### Setup

1. In VSCode, install the "LaTeX Workshop" plugin by James Yu

2. Install TexLive direct from the website.  This is required since
most Debian package repositories have an older version of TexLive.

Download: https://www.tug.org/texlive/acquire-netinstall.html

Install: https://www.tug.org/texlive/quickinstall.html

At the end of the install, it will instruct you to update `PATH`, `MANPATH`, and `INFOPATH`.
Set these in `~/.bashrc`, close your shell and re-open it to get the new environment variables.

3. Execute `sudo $(which texconfig) rehash`



# Configuration

Configuration is done via a yaml file.  

Root elements:

* secret-root-path (required)
* At least one of the following is required:
    * bbdc

Other root elements are ignored.

## SCM Configurations

The following root keys declare SCM configurations:

* bbdc (Bitbucket Data Center)

Each SCM configuration is a list of one or more SCM configurations.  This allows for some advanced configurations
to execute scans with different configurations depending on the path of the repository or the SCM that generated
the webhook.

Each scm configuration has the following elements

### service-name

Required.  A moniker for the route match that is used for reporting status.


### repo-match

Required. A regex applied to the source repository.  If the repo matches the regex, this configuration is used to
orchestrate the scanning.


### scan-config

Optional.  Contains the following elements:

#### default-scan-engines

Optional.  Default: Follows project scan configuration.

This is a dictionary in the format of:

`<engine name> : <engine configuration dictionary>`

The configuration dictionary for each engine follows the engine configuration parameters specified in 
the [Checkmarx One Scan API](https://checkmarx.stoplight.io/docs/checkmarx-one-api-reference-guide/branches/main/f601dd9456e80-run-a-scan)


#### default-scan-tags

Optional.

A dictionary of static key:value pairs that are assigned to each scan.

#### default-project-tags

Optional.

A dictionary of static key:value pairs that are assigned to each project upon project creation.


### connection

Required.  Contains values for connection parameters:

#### base-url

Required.  The base url of the SCM server.

#### shared-secret

Required.  The shared secret configured in the SCM used to sign webhook payloads.

Complexity requirements will be checked.  The shared secret must meet the following minimum criteria:

* 20 characters long
* 3 number
* 3 upper-case letters
* 2 special character


#### timeout-seconds

Optional.  Default: 60

The number of seconds before a request times out.

#### retries

Optional.  Default: 3

The number of retries when the request fails for some reason other than authorization errors.

#### ssl-verify

Optional.  Default: True

If False, server SSL certificates are not validated.

#### proxies
Optional. Default: None

A dictionary of <scheme>:<url> pairs to use a proxy server for requests.

#### api-auth
Required.  A dictionary of SCM authorization options.

Only one of the following keys can be defined:

##### token

The value specifies a file name found under the path defined by secret-root-path.

##### username/password

Two distinct key/value pairs each specifying a file name found under the path defined by secret-root-path.


#### clone-auth
Optional.  Default: The options specified by api-auth.

##### token

The value specifies a file name found under the path defined by secret-root-path.

##### username

A file name found under the path defined by secret-root-path.  If supplied with a token, the username will be
used when forming the credentials in the clone URL.

##### password

A file name found under the path defined by secret-root-path.

##### ssh

The value specifies a file name found under the path defined by secret-root-path.  The file
should contain an unencrypted private key.


### cxone

Required.  The Checkmarx One tenant connection configuration.  The following additional values
are to be configured under this key:

#### tenant

Required.

The value specifies a file name found under the path defined by secret-root-path.

#### iam-endpoint
Required.

This can be a FQDN host name or one of the following values that resolve to endpoints in the multi-tenant system:

* US
* US2
* EU
* EU2
* ANZ
* India
* Singapore


#### api-endpoint
Required.

This can be a FQDN host name or one of the following values that resolve to endpoints in the multi-tenant system:

* US
* US2
* EU
* EU2
* ANZ
* India
* Singapore




#### timeout-seconds

Optional.  Default: 60

The number of seconds before a request times out.

#### retries

Optional.  Default: 3

The number of retries when the request fails for some reason other than authorization errors.

#### ssl-verify

Optional.  Default: True

If False, server SSL certificates are not validated.

#### proxies
Optional. Default: None

A dictionary of <scheme>:<url> pairs to use a proxy server for requests.

#### api-key

Optional.  If not defined, oauth must be defined.

The value specifies a file name found under the path defined by secret-root-path.

#### oauth

Optional.  If not defined, api-key must be defined.

Additional parameters under oatuh are required:

##### client-id
Required

The value specifies a file name found under the path defined by secret-root-path.

##### client-secret
Required

The value specifies a file name found under the path defined by secret-root-path.


# Example Configurations

The following configuration uses the YAML block definitions to define common blocks
that are then used to form the configuration.  It may be easier to understand how the
YAML is parsed by transforming it to JSON [using an online conversion tool](https://onlineyamltools.com/convert-yaml-to-json).


```
secret-root-path: /run/secrets

cxone-general-connection-params: &cxone-general-connection
  timeout-seconds: 60
  retries: 3
  ssl-verify: True
  proxies:
    http: http://192.168.112.234:8080
    https: http://192.168.112.234:8080


scm-connection: &scm-connection
  base-url: http://whatever:port
  shared-secret: mysharedsecret
  <<: *general-connection

dp: &cxone_test_tenant
  tenant: dp
  api-key: test_api_key
  iam-endpoint: US
  api-endpoint: US
  <<: *cxone-general-connection

cx_ps: &cxone_prod_tenant
  tenant: cx_ps
  oauth:
    client-id: prod_client_id
    client-secret: prod_client_secret
  iam-endpoint: US
  api-endpoint: US
  <<: *cxone-general-connection


project-a-api: &bbdc-project-a-api
  username: username_scret
  password: password_secret

project-a-clone: &bbdc-project-a-clone
  token: token_secret

project-b-api: &bbdc-project-b-api
  token: token_secret

project-b-clone: &bbdc-project-b-clone
  ssh: ssh_key_secret
  token: token_secret

scan-defaults: &scm-defaults
  default-scan-engines:
    sast:
      incremental: "false"
    sca:
      exploitablePath: "true"
    apisec:

  default-scan-tags:
    foo: bar
  default-project-tags:
    foo: bar

bbdc:
  - service-name: BBDC-ProjectA
    repo-match: .*/PA
    scan-config:
      <<: *scm-defaults
    connection:
      <<: *scm-connection
      api-auth:
        <<: *bbdc-project-a-api
      clone-auth:
        <<: *bbdc-project-a-clone
    cxone:
      <<: *cxone_prod_tenant
  
  - service-name: BBDC-ProjectB
    repo-match: .*PB
    scan-config:
      <<: *scm-defaults
    connection:
      <<: *scm-connection
      api-auth:
        <<: *bbdc-project-b-api
      clone-auth:
        <<: *bbdc-project-b-clone
    cxone:
      <<: *cxone_test_tenant

```
