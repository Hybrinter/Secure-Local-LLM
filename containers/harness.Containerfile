FROM docker.io/library/debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        iproute2 \
        openssh-client \
        procps \
        python3 \
        python3-venv \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 opencode /usr/local/bin/opencode
RUN groupadd --gid 1000 agent \
    && useradd --uid 1000 --gid agent --home-dir /state --shell /usr/sbin/nologin agent \
    && mkdir -p /state \
    && chown 1000:1000 /state
USER 1000:1000
ENV HOME=/state
WORKDIR /state
