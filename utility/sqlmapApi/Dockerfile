FROM python:2.7
ENV LANG=C.UTF-8
MAINTAINER hyhm2n admin@imipy.com

RUN mkdir /app
WORKDIR /app
COPY . /app

CMD ["./sqlmap/sqlmapapi.py", "-s", "-H", "0.0.0.0", "-p", "8080"]
