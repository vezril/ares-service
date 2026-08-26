# Kali base = the off-the-shelf wireless toolbox preloaded (aircrack-ng, hcxtools,
# bettercap, hostapd, kismet) while the host stays minimal. Ares' own code is thin
# on top: the scope guard, findings schema, and orchestration.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        aircrack-ng \
        hcxtools \
        hcxdumptool \
        iw \
        wireless-tools \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# uv for a reproducible install from the locked deps.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

ENTRYPOINT ["uv", "run", "--frozen", "--no-dev", "ares"]
CMD ["--help"]
