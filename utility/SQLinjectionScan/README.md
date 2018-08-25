# SQLinjectionScan
> 使用的是Python2.7

# 目录结构
- [AKscan](./AKscan) : 爬取网站可能存在注入的url
- [sqlmap](./sqlmap-dev) : sqlmap工具
- [urls.json](./urls.json) : 爬取urls结果
- [run.py](./run.py) : 主执行文件

# 普通使用

[编译](../sqlmapApi/README.md)好 sqlmapapi 镜像。

启动：`docker run -d -p 8080:8080 hyhm2n/sqlmapapi`

```shell
$ pipenv install --dev
$ pipenv shell

$ python run.py -h
$ python run.py --target http://sublimetext.iaixue.com/ --sqlmapapi http://localhost:8080/
$ python run.py --target http://sublimetext.iaixue.com/  --timeout=1800 --depth-limit=5 --sqlmapapi http://localhost:8080/
```

# Docker link

[编译](../sqlmapApi/README.md)好 sqlmapapi 镜像。

```sh
docker build -t sqlinjectionscan:0.1 .

docker run -d --name sqlmapapi hyhm2n/sqlmapapi
docker run --rm -it --link sqlmapapi sqlinjectionscan:0.1 python run.py --target http://sublimetext.iaixue.com/ --sqlmapapi http://sqlmapapi:8080/
```

# 待完成
- [ ] 优化运行速度
- [ ] 优化spider url 过滤
