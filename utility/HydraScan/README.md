# 镜像编译

```sh
docker build -t hydra-scan:0.1 .
```

# 运行

```sh
$ docker run --rm -it hydra-scan:0.1 python3 hydraScan.py 
--target example.com 
--service ftp
```