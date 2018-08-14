# SQLinjectionScan
> 使用的是Python2.7

# 目录结构
- [AKscan](./AKscan) : 爬取网站可能存在注入的url
- [sqlmap](./sqlmap-dev) : sqlmap工具
- [urls.json](./urls.json) : 爬取urls结果
- [run.py](./run.py) : 主执行文件

# 使用
- 启动sqlmapapi之后.[如何启动?](./sqlmapApi/README.md)
```shell
$ pipenv install --dev
$ pipenv shell

$ python run.py -h 
$ python run.py --target http://sublimetext.iaixue.com/ --sqlmapapi http://localhost:8000/
$ python run.py --target http://sublimetext.iaixue.com/  --timeout=1800 --depth-limit=5 --sqlmapapi http://localhost:8000/
```

# 待完成
- [ ] 优化运行速度
- [ ] 优化spider url 过滤