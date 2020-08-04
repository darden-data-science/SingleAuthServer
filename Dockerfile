FROM ubuntu:20.04

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

RUN python3 -m pip install --upgrade --no-cache setuptools pip

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libxmlsec1-dev && \
    apt-get purge && apt-get clean

COPY . /src/SingleAuthServer

RUN python3 -m pip install /src/SingleAuthServer && \
    rm -rf tmp/SingleAuthServer

WORKDIR /srv/auth_server

RUN chown ${AUTH_SERVER_USER}:${AUTH_SERVER_USER} /srv/auth_server

# COPY authhub_config.py /etc/auth_server/authhub_config.py

# RUN chown -R ${AUTH_SERVER_USER}:${AUTH_SERVER_USER} /etc/auth-server/authhub_config.yaml

EXPOSE 8000

USER ${AUTH_SERVER_USER}

CMD ["auth_server", "--config", "/etc/auth_server/authhub_config.json"]