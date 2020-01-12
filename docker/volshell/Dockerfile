# Docker image based on Alpine Linux embedding the Volatility 3 framework (https://github.com/volatilityfoundation/volatility3).
#
# Maintained by sk4la <sk4la.box@gmail.com>.
#
# To build:
#   $ docker build -t volatility/volshell:latest .
#
# Additionaly, one can set the following build arguments (using the --build-arg option) to customize the build:
#   - DEF_ALPINE_VERSION [3.11]
#   - DEF_INSTALL_PREFIX [/usr]
#   - DEF_USERNAME [root]
#
# To run as a standalone container:
#   $ docker run -v $PWD:/case:ro --rm --cap-drop ALL -it volatility/volshell
#   $ docker run -v $PWD:/case:ro --rm --cap-drop ALL -it volatility/volshell -f /case/volatile.dmp
#
# One can also remove the ":ro" suffix (in the -v option) to allow writing to disk.
#
# See https://github.com/volatilityfoundation/volatility3 for details.

ARG DEF_ALPINE_VERSION=3.11

FROM alpine:${DEF_ALPINE_VERSION} AS builder

USER ${DEF_USERNAME}

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
RUN git clone --recursive https://github.com/VirusTotal/yara-python && \
    cd yara-python                                                  && \
    python3 setup.py build

# Fetch the symbols from the Volatility 3 framework
RUN curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip -o linux.zip     && \
    unzip linux.zip                                                                                    && \
    curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip -o mac.zip         && \
    unzip mac.zip                                                                                      && \
    curl -fL https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip -o windows.zip && \
    unzip windows.zip

RUN apk --purge del \
    .build

FROM alpine:${DEF_ALPINE_VERSION}

ARG DEF_USERNAME=root
ARG DEF_INSTALL_PREFIX=/usr

LABEL name="volshell"                                           \
      version="0.1"                                             \
      uri="https://github.com/volatilityfoundation/volatility3" \
      maintainer="sk4la <sk4la.box@gmail.com>"                  \
      status="beta"

USER ${DEF_USERNAME}

WORKDIR ${DEF_INSTALL_PREFIX}/lib

# Install system dependencies
RUN apk add --no-cache                  \
    python3                          && \
    apk add --no-cache --virtual .build \
    git

COPY --from=builder --chown="${DEF_USERNAME}:${DEF_USERNAME}" /tmp/build/yara-python yara-python

RUN find . -type d -exec chmod 755 {} \; && \
    find . -type f -exec chmod 644 {} \;

# Install the Volatility 3 framework
RUN git clone https://github.com/volatilityfoundation/volatility3.git && \
    cd volatility3                                                    && \
    python3 setup.py install                                          && \
    ln -sf ${DEF_INSTALL_PREFIX}/bin/vol ${DEF_INSTALL_PREFIX}/bin/volatility

WORKDIR ${DEF_INSTALL_PREFIX}/lib/yara-python

# Install the Python bindings for YARA
RUN python3 setup.py install

WORKDIR ${DEF_INSTALL_PREFIX}/lib/volatility3/volatility/symbols/

COPY --from=builder --chown="${DEF_USERNAME}:${DEF_USERNAME}" /tmp/build/linux linux
COPY --from=builder --chown="${DEF_USERNAME}:${DEF_USERNAME}" /tmp/build/mac mac
COPY --from=builder --chown="${DEF_USERNAME}:${DEF_USERNAME}" /tmp/build/windows windows

RUN find . -type d -exec chmod 755 {} \; && \
    find . -type f -exec chmod 644 {} \;

RUN apk --purge del \
    .build

WORKDIR /

ENTRYPOINT [ "/usr/bin/env", "volshell" ]

CMD [ "--help" ]
