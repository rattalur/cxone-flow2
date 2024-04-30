# BitBucket Data Center Test Environment

A docker image of [Bitbucket Data Cener](https://hub.docker.com/r/atlassian/bitbucket) can be created for testing purposes.


docker volume create --name bb

docker run --rm -it -v bb:/var/atlassian/application-data/bitbucket --name="bbdc" -p 80:7990 -p 7999:7999 atlassian/bitbucket:latest

It is suggested you create an entry in `hosts` to resolve a realistic domain name to `127.0.0.1` for the Bitbucket Server.  This
will make it easier to simulate a real SCM instance.

A temporary license can be obtained when starting the server.  It is recommended to use a [temporary email address](https://temp-mail.org/en/) and
interact with Bitbucket via an incognito browser.  An incognito browser will prevent interference with credentials used to log into live Atlassian
products when you have logins cached in your browser.
