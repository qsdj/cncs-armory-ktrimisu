# 镜像编译

```sh
docker build -t hyhm2n/sqlmapapi .
```

# sqlmapapi运行(使用api 方便自动化扫描)

```sh
$ docker run -d -p 8000:8080 hyhm2n/sqlmapapi
```