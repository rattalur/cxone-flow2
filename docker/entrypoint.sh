#!/bin/bash

update-ca-certificates
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

[ ! -n "$CXONEFLOW_HOSTNAME" ] && export CXONEFLOW_HOSTNAME=localhost

nginx

gunicorn --bind=127.0.0.1:5000 --name=CxOneFlow wsgi:app
