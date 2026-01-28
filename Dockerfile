FROM debian:trixie-slim

# detect DOCKER_BUILD condition/situation in install script
ENV DOCKER_BUILD true

# pre install sudo
RUN apt update && apt install -y sudo && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY ./install-dependencies.sh /
RUN /install-dependencies.sh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/workbench-script

ENTRYPOINT sh ./deploy-workbench.sh
