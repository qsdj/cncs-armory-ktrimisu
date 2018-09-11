FROM ubuntu:16.04
ENV LANG=C.UTF-8

RUN echo 'deb http://mirrors.ustc.edu.cn/ubuntu/ xenial main restricted universe multiverse' > /etc/apt/sources.list && \
    echo 'deb http://mirrors.ustc.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse' >> /etc/apt/sources.list && \
    echo 'deb http://mirrors.ustc.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse' >> /etc/apt/sources.list && \
    echo 'deb http://mirrors.ustc.edu.cn/ubuntu/ xenial-security main restricted universe multiverse' >> /etc/apt/sources.list && \
    apt update
RUN apt install nmap python ruby ruby-dev libruby gcc make --yes
RUN gem sources --add https://mirrors.ustc.edu.cn/rubygems/ --remove https://rubygems.org/ && \
    gem install bundler && \
    bundle config mirror.https://rubygems.org https://gems.ruby-china.com
COPY WhatWeb /WhatWeb
RUN cd /WhatWeb && bundle install
COPY . /app
RUN mv /WhatWeb /app/WhatWeb
WORKDIR /app
