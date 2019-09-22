FROM ubuntu:eoan

ENV DEBIAN_FRONTEND="noninteractive"
ENV PATH="${PATH}:/opt/android-ndk"
ENV ANDROID_NDK="/opt/android-ndk"
ENV ANDROID_NDK_HOME="/opt/android-ndk"
ENV MOLCH_BRANCH=master

WORKDIR /root
CMD bash

RUN apt update -y && \
	apt upgrade -y && \
	apt install -y software-properties-common && \
	#add-apt-repository -y ppa:maarten-fonville/protobuf && \
	apt update -y && \
	apt install -y sudo ca-certificates git neovim libsodium-dev build-essential libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler meson liblua5.3-dev lua5.3 swig valgrind doxygen graphviz clang clang-tools clang-tidy unzip tmux curl openjdk-8-jdk-headless
RUN curl -o android-ndk.zip https://dl.google.com/android/repository/android-ndk-r20-linux-x86_64.zip
ADD https://dl.google.com/android/repository/android-ndk-r20-linux-x86_64.zip android-ndk.zip
RUN unzip android-ndk.zip && \
	mkdir -p /opt && \
	mv android-ndk-r20 /opt/android-ndk
COPY . /root/molch
