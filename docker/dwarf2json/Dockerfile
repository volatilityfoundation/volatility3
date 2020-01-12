# Docker image based on Alpine Linux embedding the Volatility 3 framework (https://github.com/volatilityfoundation/volatility3).
#
# Maintained by sk4la <sk4la.box@gmail.com>.
#
# To build:
#   $ docker build -t volatility/dwarf2json:latest .
#
# Additionaly, one can set the following build arguments (using the --build-arg option) to customize the build:
#   - DEF_ALPINE_VERSION [3.11]
#   - DEF_INSTALL_PREFIX [/usr]
#   - DEF_USERNAME [root]
#
# To run as a standalone container:
#   $ docker run -v $PWD:/case:ro --rm --cap-drop ALL -it volatility/dwarf2json
#
# One can also remove the ":ro" suffix (in the -v option) to allow writing to disk.
#
# See https://github.com/volatilityfoundation/volatility3 for details.

ARG DEF_ALPINE_VERSION=3.11

FROM alpine:${DEF_ALPINE_VERSION} AS builder

ARG DEF_USERNAME=root

USER ${DEF_USERNAME}

WORKDIR /tmp/build/

# Install system dependencies
RUN apk add --no-cache --virtual .build \
    git                                 \
    go                                  \
    musl-dev

# Fetch the online repository
RUN git clone https://github.com/volatilityfoundation/dwarf2json.git

WORKDIR /tmp/build/dwarf2json

# Build the tool
RUN go build

RUN apk --purge del \
    .build

FROM alpine:${DEF_ALPINE_VERSION}

ARG DEF_USERNAME=root
ARG DEF_INSTALL_PREFIX=/usr

LABEL name="dwarf2json"                                         \
      version="0.1"                                             \
      uri="https://github.com/volatilityfoundation/volatility3" \
      maintainer="sk4la <sk4la.box@gmail.com>"                  \
      status="beta"

USER ${DEF_USERNAME}

WORKDIR ${DEF_INSTALL_PREFIX}/bin

COPY --from=builder --chown="${DEF_USERNAME}:${DEF_USERNAME}" /tmp/build/dwarf2json/dwarf2json dwarf2json

RUN chmod 755 dwarf2json

WORKDIR /

ENTRYPOINT [ "/usr/bin/dwarf2json" ]

CMD [ "--help" ]
