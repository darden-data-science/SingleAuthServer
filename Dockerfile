FROM ubuntu:20.04

# Build provenance. Supplied by build-image.sh; the defaults below only apply to
# a bare `docker build`, which is why they say "unknown" rather than a version
# number that would silently lie.
#
#   docker inspect --format '{{json .Config.Labels}}' <image>
#
# tells you the exact commit any deployed container was built from. Without this
# an image tagged :latest is unidentifiable after the fact — which is the reason
# there was previously no rollback path.
ARG VERSION=unknown
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="SingleAuthServer" \
      org.opencontainers.image.description="Cluster-wide external auth service for JupyterHub." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/darden-data-science/SingleAuthServer" \
      org.opencontainers.image.licenses="BSD-3-Clause"

# Also as env, so a running container can report its own identity without a
# `docker inspect` from outside — useful when debugging a pod in-cluster.
ENV SINGLE_AUTH_SERVER_VERSION="${VERSION}" \
    SINGLE_AUTH_SERVER_GIT_SHA="${GIT_SHA}"

ENV TZ=America/New_York
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      git \
      vim \
      less \
      python3 \
      python3-dev \
      python3-pip \
      python3-setuptools \
      python3-wheel \
      libssl-dev \
      libcurl4-openssl-dev \
      build-essential \
      sqlite3 \
      curl \
      dnsutils \
      && \
    apt-get purge && apt-get clean


ARG AUTH_SERVER_USER=jovyan
ARG AUTH_SERVER_UID=1000

ARG HOME=/home/jovyan

ENV LANG C.UTF-8

RUN adduser --disabled-password \
    --gecos "Default user" \
    --uid ${AUTH_SERVER_UID} \
    --home ${HOME} \
    --force-badname \
    ${AUTH_SERVER_USER}

RUN python3 -m pip install --upgrade --no-cache setuptools pip uv

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libxmlsec1-dev && \
    apt-get purge && apt-get clean

COPY . /src/SingleAuthServer

WORKDIR /src/SingleAuthServer

RUN UV_LINK_MODE=copy uv sync --frozen --extra saml

WORKDIR /srv/auth_server

ENV PATH="/src/SingleAuthServer/.venv/bin:${PATH}"

RUN chown ${AUTH_SERVER_USER}:${AUTH_SERVER_USER} /srv/auth_server

# COPY authhub_config.py /etc/auth_server/authhub_config.py

# RUN chown -R ${AUTH_SERVER_USER}:${AUTH_SERVER_USER} /etc/auth-server/authhub_config.yaml

EXPOSE 8000

USER ${AUTH_SERVER_USER}

CMD ["auth_server", "--config", "/etc/auth_server/authhub_config.py"]
