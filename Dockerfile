FROM ubuntu:cosmic

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt update -y && \
	apt upgrade -y && \
	apt install -y software-properties-common && \
	add-apt-repository -y ppa:maarten-fonville/protobuf && \
	apt update -y && \
	apt install -y sudo ca-certificates git neovim libsodium-dev build-essential libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler meson liblua5.3-dev lua5.3 swig valgrind doxygen graphviz clang clang-tools clang-tidy
