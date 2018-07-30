FROM python:3

RUN set -ex && mkdir -p ~/.pip
RUN echo "[global]" > ~/.pip/pip.conf && \
    echo "index-url = https://mirrors.ustc.edu.cn/pypi/web/simple" >> ~/.pip/pip.conf && \
    echo "format = columns" >> ~/.pip/pip.conf && \
    pip install pipenv

# -- Install Application into container:
RUN set -ex && mkdir /app

WORKDIR /app
COPY . /app
RUN pipenv install --system --deploy && \
    python setup.py install
