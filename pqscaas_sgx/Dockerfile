# Dockerfile — PQSCAAS SGX experiment build environment
#
# Provides Intel SGX SDK (sim mode) + OpenSSL + build tools on Ubuntu 22.04.
# Required on macOS (no native SGX SDK) or any Linux without the SDK installed.
#
# Build:
#   docker build -t pqscaas-sgx .
#
# Run (mounts project directory for results):
#   docker run --platform linux/amd64 --rm -it \
#     -v $(pwd):/pqscaas_sgx \
#     pqscaas-sgx
#
# Inside container:
#   source /opt/intel/sgxsdk/environment
#   make SGX_MODE=SIM
#   ./pqscaas_experiments
#   python3 plot_all.py

FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------------------
# System packages
# --------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential g++ make cmake git wget curl \
    libssl-dev openssl \
    python3 python3-pip \
    ca-certificates gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------------------------------
# Intel SGX SDK (simulation mode — no driver needed)
# --------------------------------------------------------------------------
ARG SGX_SDK_VERSION=2.25.100.3
ARG SGX_SDK_BIN=sgx_linux_x64_sdk_${SGX_SDK_VERSION}.bin

RUN wget -q "https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu22.04-server/${SGX_SDK_BIN}" \
    || wget -q "https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/${SGX_SDK_BIN}" \
    && chmod +x ${SGX_SDK_BIN} \
    && echo "yes" | ./${SGX_SDK_BIN} \
    && rm ${SGX_SDK_BIN}

# SDK installs to /sgxsdk with current installer defaults
ENV SGX_SDK=/sgxsdk
ENV PATH=${SGX_SDK}/bin:${SGX_SDK}/bin/x64:${PATH}
ENV PKG_CONFIG_PATH=${SGX_SDK}/pkgconfig:${PKG_CONFIG_PATH:-}
ENV LD_LIBRARY_PATH=${SGX_SDK}/sdk_libs:${LD_LIBRARY_PATH:-}

# --------------------------------------------------------------------------
# Python plotting dependencies
# --------------------------------------------------------------------------
RUN pip3 install --no-cache-dir pandas matplotlib numpy

# --------------------------------------------------------------------------
# Working directory
# --------------------------------------------------------------------------
WORKDIR /pqscaas_sgx
COPY . /pqscaas_sgx/

RUN echo 'source /sgxsdk/environment' >> /root/.bashrc

CMD ["/bin/bash", "-c", \
    "source /sgxsdk/environment && \
      make SGX_MODE=SIM && \
      echo 'Build OK — run ./pqscaas_experiments' && \
      /bin/bash"]
