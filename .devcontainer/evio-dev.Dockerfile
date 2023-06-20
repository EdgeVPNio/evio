FROM ubuntu:jammy AS withuser
# ********************************************************
# * Setup basic environment                              *
# ********************************************************
ARG USERNAME=evio
# replace 1000 with FS UID that owns src code
ARG USER_UID=1000 
ARG USER_GID=$USER_UID
ARG DEBIAN_FRONTEND=noninteractive
# ENV persists in the container
ENV TZ=Etc/UTC
# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    #
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# ********************************************************
# * Install software packages                            *
# ********************************************************
FROM withuser AS evio-base
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get install -y \
        git \
        iputils-ping \
        libffi-dev \
        software-properties-common \    
        iproute2 \
        openvswitch-switch \
        tcpdump \
        python3.10 \
        python3.10-dev \
        python3.10-venv \
        python3-pip \
        python3-wheel

WORKDIR /workspace
ENV VIRTUAL_ENV=./venv
RUN python3.10 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN pip3 install --upgrade pip && \
    pip3 --cache-dir /var/cache/evio/ \
        install wheel && \
    pip3 --cache-dir /var/cache/evio/ \
         install eventlet==0.30.2 psutil \
         slixmpp requests simplejson \
         pyroute2 keyring ryu flake8

# ********************************************************
# * Run clean up or anything that changes often                            *
# ********************************************************         
#RUN systemctl mask getty@tty1.service
# [Optional] Set the default user. Omit if you want to keep the default as root.
USER $USERNAME

# CMD [/bin/bash -c "while sleep 1000; do :; done"]