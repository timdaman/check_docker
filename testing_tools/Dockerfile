FROM ubuntu:18.04 AS build

ENV PYENV_ROOT="/pyenv"
ENV PATH="$PYENV_ROOT/bin:$PATH"
WORKDIR /
RUN apt update
RUN apt install --no-install-recommends --fix-missing -y build-essential make locales libssl1.1 libssl-dev \
    libffi-dev libbz2-dev libreadline-dev libsqlite3-dev libjpeg-dev zlib1g-dev libxml2-dev libxslt1-dev \
    curl ca-certificates
RUN curl -kL https://github.com/pyenv/pyenv/archive/master.tar.gz | tar -xz \
    && mv pyenv-master /pyenv
RUN echo 3.5.6 3.6.7 3.7.1 | xargs -n 1 -P $(nproc) pyenv install
RUN /pyenv/versions/3.7.1/bin/pip3.7 install setuptools wheel flit tox

FROM ubuntu:18.04
SHELL ["/bin/bash", "-lc"]
ENTRYPOINT ["/bin/bash", "-lc"]
RUN apt update \
    && apt install --no-install-recommends --fix-missing -y git libssl1.0.0 libssl1.1 ca-certificates netbase \
    && apt-get autoremove -y \
    && apt-get clean all \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /pyenv /pyenv
ENV PYENV_ROOT="/pyenv"
RUN echo 'PATH="/pyenv/bin:$PATH"' >> /etc/profile.d/02-pyenv.sh
RUN echo 'eval "$(pyenv init -)"' >> /etc/profile.d/02-pyenv.sh
RUN echo 'pyenv global 3.5.6 3.6.7 3.7.1' >> /etc/profile.d/02-pyenv.sh
# These are needed for some tests
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV isolated=true