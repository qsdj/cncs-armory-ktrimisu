# 镜像编译

```sh
docker build -t asset-finder:0.1 .
```

# 运行

```sh
docker run --rm -it asset-finder:0.1 python FindAssets.py -u 192.168.1.1-192.168.1.2
```
