#!/bin/bash

[ ! -n "$HOSTNAME" ] && export HOSTNAME=localhost
[ -n "$SSL_CERT_PATH" ] && rm /etc/nginx/sites-enabled/cxoneflow-http || rm /etc/nginx/sites-enabled/cxoneflow-https

gunicorn --bind=127.0.0.1:5000 --name=CxOneFlow wsgi:app

bash
