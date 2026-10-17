ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        openssh-server \
        python3 \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1000 git \
    && useradd --uid 1000 --gid git --home-dir /srv/git --shell /bin/sh \
        --password '*' git \
    && mkdir -p /srv/git /repos /opt/local-agent/hooks \
        /usr/local/lib/local-agent \
    && chown 1000:1000 /srv/git /repos
COPY --chmod=0644 sshd_config /etc/ssh/sshd_config_fixture
COPY --chmod=0755 serve_git.py /usr/local/lib/local-agent/serve_git.py
COPY --chmod=0755 pre_receive.py /opt/local-agent/hooks/pre-receive
USER 1000:1000
ENV HOME=/srv/git
WORKDIR /srv/git
RUN git init --bare --object-format=sha1 --initial-branch=main /repos/demo.git
