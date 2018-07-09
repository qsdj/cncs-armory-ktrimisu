FROM python:2

RUN set -ex && mkdir -p ~/.pip
RUN echo "[global]" > ~/.pip/pip.conf
RUN echo "index-url = https://mirrors.ustc.edu.cn/pypi/web/simple" >> ~/.pip/pip.conf
RUN echo "format = columns" >> ~/.pip/pip.conf
RUN pip install pipenv

# -- Install Application into container:
RUN set -ex && mkdir /app

WORKDIR /app

COPY . /app

COPY Pipfile Pipfile
RUN pipenv install && pipenv install '-e .' --dev
