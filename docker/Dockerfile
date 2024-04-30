FROM ubuntu:24.04
LABEL org.opencontainers.image.source https://github.com/checkmarx-ts/cxone-flow
LABEL org.opencontainers.image.vendor Checkmarx Professional Services
LABEL org.opencontainers.image.title Checkmarx One Flow
LABEL org.opencontainers.image.description Orchestrates scans for Checkmarx One

USER root
WORKDIR /opt/cxone

COPY *.txt /opt/cxone

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata && \
    apt-get install -y python3.12 python3-pip nginx bash && \
    pip install -r requirements.txt --no-cache-dir --break-system-packages && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm requirements.txt && \
    rm /etc/nginx/sites-enabled/default


RUN usermod -s /bin/bash nobody && \
    groupadd nobody && \
    usermod -G nobody nobody && \
    mkdir -p /opt/cxone && \
    mkdir -p /var/log/gunicorn && \
    mkdir -p /var/log/cxoneflow && \
    mkdir -p /var/log/nginx && \
    chown root:nobody /var/log/gunicorn && \
    chmod 775 /var/log/gunicorn && \
    chown root:nobody /var/log/cxoneflow && \
    chmod 775 /var/log/cxoneflow


COPY *.py /opt/cxone/
COPY docker/entrypoint.sh /opt/cxone
COPY docker/*.py /opt/cxone
COPY docker/logging.json /opt/cxone
COPY docker/nginx /etc/nginx/sites-enabled/

COPY api_utils /opt/cxone/api_utils
COPY config /opt/cxone/config
COPY cxone_api /opt/cxone/cxone_api
COPY cxone_service /opt/cxone/cxone_service
COPY cxoneflow_logging /opt/cxone/cxoneflow_logging
COPY orchestration /opt/cxone/orchestration
COPY scm_services /opt/cxone/scm_services
COPY status /opt/cxone/status
COPY task_management /opt/cxone/task_management

RUN chown root:nobody /etc/nginx/sites-enabled/*

USER nobody

ENTRYPOINT ["/opt/cxone/entrypoint.sh"]
