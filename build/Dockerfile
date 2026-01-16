# Frida Patch Testing Framework - Build Environment
# Ubuntu 22.04 with all Frida build dependencies
#
# This Dockerfile sets up a complete build environment for compiling
# Frida from source with custom patches.

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set locale to avoid build warnings
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install base dependencies (without nodejs - we'll install newer version)
RUN apt-get update && apt-get install -y \
    # Core build tools
    build-essential \
    git \
    curl \
    wget \
    cmake \
    ninja-build \
    # Python (for Frida build system and config parsing)
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    # Compression and archive tools
    xz-utils \
    bzip2 \
    unzip \
    zip \
    # Additional build tools
    pkg-config \
    libtool \
    automake \
    autoconf \
    flex \
    bison \
    # Development libraries
    libglib2.0-dev \
    libffi-dev \
    libssl-dev \
    libdwarf-dev \
    libelf-dev \
    libunwind-dev \
    libc6-dev \
    # Additional utilities
    patch \
    file \
    ca-certificates \
    jq \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 LTS (required by Frida >= 17.x)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version && npm --version

# Install architecture-specific cross-compilation tools if available
# These are optional and only needed for cross-compilation
RUN apt-get update && apt-get install -y \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    binutils-aarch64-linux-gnu \
    2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for Frida build system
RUN pip3 install --no-cache-dir \
    pyyaml \
    meson \
    ninja \
    setuptools \
    wheel

# Install Node.js tools needed by Frida build
RUN npm install -g \
    node-gyp \
    typescript

# Create build directories
RUN mkdir -p /build/frida /build/output /build/patches /build/logs

# Set working directory
WORKDIR /build

# Copy build scripts
COPY build.sh /build/
COPY scripts/ /build/scripts/

# Make scripts executable
RUN chmod +x /build/build.sh 2>/dev/null || true && \
    chmod +x /build/scripts/*.sh 2>/dev/null || true && \
    chmod +x /build/scripts/*.py 2>/dev/null || true

# Entry point
ENTRYPOINT ["/build/build.sh"]

# Default command (can be overridden)
CMD ["--help"]
