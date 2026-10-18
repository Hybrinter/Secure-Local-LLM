ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS build
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
    && rm -rf /var/lib/apt/lists/*
COPY src /src
WORKDIR /src
RUN cmake -B build \
        -DGGML_NATIVE=OFF \
        -DGGML_BACKEND_DL=ON \
        -DGGML_CPU_ALL_VARIANTS=ON \
        -DLLAMA_BUILD_TESTS=OFF \
        -DLLAMA_BUILD_EXAMPLES=OFF \
        -DLLAMA_BUILD_APP=OFF \
        -DLLAMA_BUILD_UI=OFF \
        -DLLAMA_USE_PREBUILT_UI=OFF \
        -DLLAMA_SUBPROCESS=OFF \
        -DLLAMA_OPENSSL=OFF \
        -DLLAMA_BUILD_TOOLS=ON \
        -DLLAMA_BUILD_COMMON=ON \
        -DLLAMA_BUILD_SERVER=ON \
    && cmake --build build --target llama-server -j4

FROM ${BASE_IMAGE}
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        libgomp1 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 agent \
    && useradd --uid 1000 --gid agent --home-dir /state --shell /usr/sbin/nologin agent \
    && mkdir -p /state \
    && chown 1000:1000 /state
COPY --from=build /src/build/bin /opt/llama
ENV LD_LIBRARY_PATH=/opt/llama
USER 1000:1000
ENV HOME=/state
WORKDIR /state
