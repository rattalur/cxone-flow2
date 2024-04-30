#!/bin/bash

[ ! -n "$CXONEFLOW_HOSTNAME" ] && export CXONEFLOW_HOSTNAME=localhost
[ -n "$SSL_CERT_PATH" ] && rm /etc/nginx/sites-enabled/cxoneflow-http || rm /etc/nginx/sites-enabled/cxoneflow-https

nginx

gunicorn --bind=127.0.0.1:5000 --name=CxOneFlow wsgi:app
