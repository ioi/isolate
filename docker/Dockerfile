# syntax=docker/dockerfile:1

# Step 1: A working ubuntu version
FROM ubuntu:jammy AS base-ubuntu

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get upgrade -y

# Step 2: Build isolate
FROM base-ubuntu AS build

WORKDIR /isolate

# Install tzdata non-interactively: https://serverfault.com/a/1016972
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y tzdata && \
    apt-get install -y build-essential libcap-dev pkg-config libsystemd-dev

COPY . .

# Compile elements
RUN make isolate isolate-check-environment isolate-cg-keeper
RUN make DESTDIR=/build install -o *
COPY docker/start_isolate.sh /build/usr/local/sbin/start_isolate

# Step 3: Final image
FROM base-ubuntu

# Isolate dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get install -y libcap-dev libsystemd-dev

# Install isolate
COPY --from=build /build/ /

# Pass all arguments to isolate-check-environment
ENTRYPOINT ["start_isolate"]
