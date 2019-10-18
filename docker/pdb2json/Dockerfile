# Docker image based on Alpine Linux embedding the Volatility 3 framework (https://github.com/volatilityfoundation/volatility3).
#
# Maintained by sk4la <sk4la.box@gmail.com>.
#
# To build:
#   $ docker build -t volatilityfoundation/pdb2json:latest .
#
# Additionaly, one can set the following build arguments (using the --build-arg option) to customize the build:
#   - DEF_ALPINE_VERSION [3.10]
#   - DEF_INSTALL_PREFIX [/usr]
#   - DEF_USERNAME [root]
#
# To run as a standalone container:
#   $ docker run -v "${PWD}:/case" --rm --cap-drop=ALL volatilityfoundation/pdb2json
#   $ docker run -v "${PWD}:/case" --rm --cap-drop=ALL volatilityfoundation/pdb2json -f /case/ntkrnlmp.pdb -o /case/ntkrnlmp.json
#
# See https://github.com/volatilityfoundation/volatility3 for details.

ARG DEF_ALPINE_VERSION=3.10

FROM alpine:${DEF_ALPINE_VERSION}

ARG DEF_USERNAME=root
ARG DEF_INSTALL_PREFIX=/usr

LABEL name="pdb2json"                                           \
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
    gcc                                 \
    git                                 \
    musl-dev                            \
    python3-dev


# Install the Volatility 3 framework
RUN git clone https://github.com/volatilityfoundation/volatility3.git      && \
    cd volatility3                                                         && \
    python3 setup.py install                                               && \
    ln -sf ${DEF_INSTALL_PREFIX}/bin/vol ${DEF_INSTALL_PREFIX}/bin/volatility

RUN python3 -m pip install --no-cache --upgrade \
    pdbparse                                    \
    pip

RUN apk --purge del \
    .build

WORKDIR /

ENTRYPOINT [ "python3", "/usr/lib/volatility3/development/pdbparse-to-json.py" ]

CMD [ "-h" ]
