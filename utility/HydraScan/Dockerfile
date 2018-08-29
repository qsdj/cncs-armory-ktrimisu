FROM ubuntu:16.04
ENV LANG=C.UTF-8

RUN mkdir /app
RUN echo 'deb http://mirrors.ustc.edu.cn/ubuntu/ xenial main restricted universe multiverse' > /etc/apt/sources.list && \
    echo 'deb http://mirrors.ustc.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse' >> /etc/apt/sources.list && \
    echo 'deb http://mirrors.ustc.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse' >> /etc/apt/sources.list && \
    echo 'deb http://mirrors.ustc.edu.cn/ubuntu/ xenial-security main restricted universe multiverse' >> /etc/apt/sources.list && \
    apt update

RUN apt install python3 hydra --yes
COPY . /app
WORKDIR /app
