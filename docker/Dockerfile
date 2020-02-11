# Docker image based on Alpine Linux embedding the Volatility 3 framework (https://github.com/volatilityfoundation/volatility3).
#
# To build:
#   $ make
#
# Additionaly, one can set the following build arguments (using the Makefile variable) to customize the build:
#   - ALPINE_VERSION [3.11]
#   - USERNAME [root]
#

ARG ALPINE_VERSION=3.11

#
# Volatility builder image
#

FROM alpine:${ALPINE_VERSION} AS builder

ARG USERNAME=root

USER ${USERNAME}

WORKDIR /tmp/build/

# Install system dependencies
RUN apk add --no-cache --virtual .build \
    curl                                \
    gcc                                 \
    git                                 \
    musl-dev                            \
    python3-dev                         \
    unzip

# Build the Python bindings for YARA
RUN git clone --recursive https://github.com/VirusTotal/yara-python   && \
    cd yara-python                                                    && \
    python3 setup.py install --root /tmp/root                         && \
    # build and install volatility
    git clone https://github.com/volatilityfoundation/volatility3.git && \
    cd volatility3                                                    && \
    python3 setup.py install --root /tmp/root                         && \
    # build and install pdbparse
    python3 -m pip install --root /tmp/root pdbparse                  && \
    apk --purge del .build

#
# Volatility generic image
#

FROM alpine:${ALPINE_VERSION} as volbase

ARG USERNAME=root

USER ${USERNAME}

WORKDIR /usr/lib

# Install system dependencies
RUN apk add --no-cache                          \
    python3 capstone                         && \
    python3 -m pip install --no-cache           \
    pefile capstone

# Copy built yara and volatility files
COPY --from=builder /tmp/root /

# Create links and mount for symbols
RUN mkdir -p /symbols                                       && \
    mkdir /symbols/mac                                      && \
    mkdir /symbols/linux                                    && \
    mkdir /symbols/windows                                  && \
    ln -sf /symbols/mac \
       /usr/lib/python3.8/site-packages/volatility/symbols  && \
    ln -sf /symbols/linux \
       /usr/lib/python3.8/site-packages/volatility/symbols  && \
    ln -sf /symbols/windows \
      /usr/lib/python3.8/site-packages/volatility/symbols

VOLUME [ "/symbols" ]

WORKDIR /

#
# Vol image
#
# To run as a standalone container:
#   $ docker run -v /dir/to/symbols:/symbols -v /dir/to/image:/case:ro --rm --cap-drop ALL volatility/vol -f /case/data.lime windows.info
#
# One can also remove the ":ro" suffix (in the -v option) to allow writing to disk.
#
# See https://github.com/volatilityfoundation/volatility3 for details.
FROM volbase as vol

LABEL name="vol"                                                              \
      version="0.1"                                                           \
      uri="https://github.com/volatilityfoundation/volatility3"               \
      maintainer="Volatility Foundation <volatility@volatilityfoundation.org>"\
      status="beta"

ENTRYPOINT [ "/usr/bin/env", "vol" ]

CMD [ "--help" ]

#
# Volshell image
#
# To run as a standalone container:
#   $ docker run -v /dir/to/symbols:/symbols -v /dir/to/image:/case:ro --rm --cap-drop ALL volatility/volshell -f /case/data.lime -w
#
# One can also remove the ":ro" suffix (in the -v option) to allow writing to disk.
#
# See https://github.com/volatilityfoundation/volatility3 for details.

FROM volbase as volshell

LABEL name="volshell"                                                         \
      version="0.1"                                                           \
      uri="https://github.com/volatilityfoundation/volatility3"               \
      maintainer="Volatility Foundation <volatility@volatilityfoundation.org>"\
      status="beta"

ENTRYPOINT [ "/usr/bin/env", "volshell" ]

CMD [ "--help" ]

#
# Pdbconf image
#
# To run as a standalone container:
#   $ docker run -v /dir/to/symbols:/symbols --rm --cap-drop ALL volatility/pdbconv -f /symbols/ntkrnlmp.pdb -o /symbols/ntkrnlmp.json
#
# See https://github.com/volatilityfoundation/volatility3 for details
FROM volbase as pdbconv
LABEL name="pdbconv"                                                          \
      version="0.1"                                                           \
      uri="https://github.com/volatilityfoundation/volatility3"               \
      maintainer="Volatility Foundation <volatility@volatilityfoundation.org>"\
      status="beta"

ENTRYPOINT [ "/usr/bin/env", "python3", "/usr/lib/python3.8/site-packages/volatility/framework/symbols/windows/pdbconv.py"]

CMD [ "--help" ]