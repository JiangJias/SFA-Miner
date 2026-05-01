# SFA-Miner Dockerfile
# Multi-stage build for optimized image size

# Stage 1: Build environment
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    python3-dev \
    libssl-dev \
    libffi-dev \
    ninja-build \
    zlib1g-dev \
    libtinfo-dev \
    libxml2-dev \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Install LLVM 16
ARG LLVM_VERSION=16.0.0
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
    && tar xf clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
    && mv clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04 /opt/llvm-${LLVM_VERSION} \
    && rm clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz

# Set LLVM environment
ENV LLVM_DIR=/opt/llvm-${LLVM_VERSION}
ENV PATH=${LLVM_DIR}/bin:${PATH}
ENV LD_LIBRARY_PATH=${LLVM_DIR}/lib:${LD_LIBRARY_PATH}

# Install Z3 Theorem Prover
RUN git clone --depth 1 https://github.com/Z3Prover/z3.git /build/z3 \
    && cd /build/z3 \
    && python3 scripts/mk_make.py --prefix=/opt/z3 \
    && cd build \
    && make -j$(nproc) \
    && make install \
    && cd / \
    && rm -rf /build/z3

ENV Z3_DIR=/opt/z3
ENV LD_LIBRARY_PATH=${Z3_DIR}/lib:${LD_LIBRARY_PATH}

# Install SVF
RUN git clone https://github.com/SVF-tools/SVF.git /build/SVF \
    && cd /build/SVF \
    && mkdir Release-build && cd Release-build \
    && cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_DIR=${LLVM_DIR} \
        -DZ3_DIR=${Z3_DIR} \
    && make -j$(nproc) \
    && cd / \
    && mkdir -p /opt/SVF \
    && cp -r /build/SVF/Release-build /opt/SVF/ \
    && cp -r /build/SVF/svf /opt/SVF/ \
    && cp -r /build/SVF/svf-llvm /opt/SVF/ \
    && rm -rf /build/SVF

ENV SVF_DIR=/opt/SVF
ENV PATH=${SVF_DIR}/Release-build/bin:${PATH}

# Stage 2: Runtime environment
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libstdc++6 \
    libgcc1 \
    libgomp1 \
    zlib1g \
    libtinfo6 \
    graphviz \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Copy LLVM from builder
COPY --from=builder /opt/llvm-16.0.0 /opt/llvm-16.0.0

# Copy Z3 from builder
COPY --from=builder /opt/z3 /opt/z3

# Copy SVF from builder
COPY --from=builder /opt/SVF /opt/SVF

# Set environment variables
ENV LLVM_DIR=/opt/llvm-16.0.0
ENV Z3_DIR=/opt/z3
ENV SVF_DIR=/opt/SVF
ENV PATH=${SVF_DIR}/Release-build/bin:${LLVM_DIR}/bin:/workspace/bin:${PATH}
ENV LD_LIBRARY_PATH=${Z3_DIR}/lib:${LLVM_DIR}/lib:${LD_LIBRARY_PATH}

# Install Python packages
RUN pip3 install --no-cache-dir \
    bitarray \
    graphviz

# Create workspace
WORKDIR /workspace

# Copy SFA-Miner source code
COPY SFAMiner.py /workspace/
COPY src/ /workspace/src/
COPY CMakeLists.txt /workspace/
COPY compile.sh /workspace/
COPY example.c /workspace/
COPY example.ll /workspace/

# Make scripts executable
RUN chmod +x /workspace/compile.sh

# Build SFA-Miner
RUN mkdir -p /workspace/build && cd /workspace/build \
    && cmake .. \
        -DLLVM_DIR=${LLVM_DIR} \
        -DZ3_DIR=${Z3_DIR} \
        -DSVF_DIR=${SVF_DIR} \
    && make -j$(nproc) \
    && mkdir -p /workspace/bin \
    && cp svf-ex /workspace/bin/ \
    && cd /workspace \
    && rm -rf /workspace/build

# Create data directory for mounting
RUN mkdir -p /workspace/data /workspace/output

# Create environment info script
RUN echo '#!/bin/bash\n\
echo "================================="\n\
echo "  SFA-Miner Docker Container"\n\
echo "================================="\n\
echo ""\n\
echo "Environment:"\n\
echo "  LLVM: $LLVM_DIR"\n\
echo "  Z3: $Z3_DIR"\n\
echo "  SVF: $SVF_DIR"\n\
echo ""\n\
echo "Available commands:"\n\
echo "  clang          - LLVM C compiler"\n\
echo "  opt            - LLVM optimizer"\n\
echo "  svf-ex         - SFA-Miner SVF driver"\n\
echo "  python3        - Python 3 interpreter"\n\
echo ""\n\
echo "Usage:"\n\
echo "  1. Compile C code to LLVM IR:"\n\
echo "     ./compile.sh your_code.c"\n\
echo ""\n\
echo "  2. Run SFA-Miner:"\n\
echo "     python3 SFAMiner.py -s=SymbolicAPIPathGenerator -d=SFA.db -i=./data -o=./output -a=openssl"\n\
echo ""\n\
echo "  3. See help:"\n\
echo "     python3 SFAMiner.py --help"\n\
echo ""\n\
echo "Mount your data to /workspace/data:"\n\
echo "  docker run -v /path/to/data:/workspace/data sfa-miner"\n\
echo "================================="\n\
' > /usr/local/bin/info && chmod +x /usr/local/bin/info

# Verify installation
RUN clang --version \
    && opt --version \
    && python3 --version \
    && python3 -c "import bitarray; import graphviz; print('Python packages OK')" \
    && test -f /workspace/bin/svf-ex && echo "svf-ex: OK" \
    && test -f /workspace/SFAMiner.py && echo "SFAMiner.py: OK"

# Set default command
CMD ["/bin/bash", "-c", "info && /bin/bash"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 --version || exit 1

# Labels
LABEL maintainer="SFA-Miner Team"
LABEL description="SFA-Miner: API Usage Pattern Mining and Misuse Detection Tool"
LABEL version="1.0"
LABEL org.opencontainers.image.source="https://github.com/JiangJias/SFA-Miner"

# Expose no ports (command-line tool only)

# Set working directory for user
WORKDIR /workspace
