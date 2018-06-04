# Docker 镜像

项目根目录

`docker build -t cscanpoc -f ./Dockerfile-bundle .`

执行如下命令获取 `poc_id` -> `POC_MODULE` 的映射（JSON 文件）

`pipenv run python scripts/indexing.py CScanPoc/pocs <输出JSON文件>`

执行 POC:

`docker run -e POC_MODULE=<对应上面脚本获取 POC_MODULE> -e POC_ARGS='-u http://www.shit.com' --rm cscanpoc`

例如

`docker run -e POC_MODULE=CScanPoc.pocs.info_webinf -e POC_ARGS='-u http://www.baidu.com' --rm cscanpoc`

# 同步

```sh
pipenv run python scripts/sync.py --help
usage: sync.py [-h] --host HOST --user USER --db DB [--pass PASSWD] [--update]
               [--insert] [--poc] [--vuln] --target TARGET [-v] [-vv]

optional arguments:
  -h, --help       show this help message and exit
  --host HOST      数据库地址
  --user USER      数据库用户
  --db DB          数据库名
  --pass PASSWD    数据库密码
  --update         执行更新操作
  --insert         执行插入操作
  --poc            设定 poc 为操作对象，可以和 --vuln 选项同时使用
  --vuln           设定 vuln 为操作对象，可以和 --poc 选项同时使用
  --target TARGET  目标目录/文件
  -v               verbose
  -vv              very verbose
```

示例：

插入目录 `path/to/pocs` 中所有的 poc 和 vuln 到数据库：

```sh
pipenv run python scripts/sync.py --host ... --user ... --db ... --pass ... \
  --insert --poc --vuln --target path/to/pocs
```

更新目录 `path/to/pocs` 中所有的 poc 和 vuln 到数据库：

```sh
pipenv run python scripts/sync.py --host ... --user ... --db ... --pass ... \
  --update --poc --vuln --target path/to/pocs
```

也可以只更新某个文件 `/path/to/pocs/shit_poc.py`：

```sh
pipenv run python scripts/sync.py --host ... --user ... --db ... --pass ... \
  --update --poc --vuln --target path/to/pocs/shit_poc.py
```
