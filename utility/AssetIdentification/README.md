# 镜像编译

```sh
docker build -t asset-identifier:0.1 .
```

# 运行

```sh
docker run --rm -it -v /tmp/mm:/tmp/mm \
    asset-identifier:0.1 python what_web.py \
    -u www.taobao.com \
    --json-out-file /tmp/mm/nmap.json
```

```sh
docker run --rm -it -v /tmp/mm:/tmp/mm \
    asset-identifier:0.1 python nmap_svc_scan.py \
    -u www.taobao.com \
    --json-out-file /tmp/mm/nmap.json
```
