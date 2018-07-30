# 功能脚本

```sh
$ python scripts/utils.py
usage: utils.py [-h] [--sort] [--host HOST] [--user USER] [--db DB]
                [--port PORT] [--pass PASSWD] --poc-dir POC_DIR [-v] [-vv]
                [--index-dir INDEX_DIR] [--skip-indexing] [--update]

optional arguments:
  -h, --help            show this help message and exit
  --sort                整理 POC 将所有 POC 放置到 产品类型/产品名 目录中
  --host HOST           数据库地址
  --user USER           数据库用户
  --db DB               数据库名
  --port PORT           数据库端口
  --pass PASSWD         数据库密码
  --poc-dir POC_DIR     目标目录，将递归处理目录下所有 .py 结尾文件
  -v                    verbose
  -vv                   very verbose
  --index-dir INDEX_DIR
                        索引信息存放目录，默认当前目录 index 目录下
  --skip-indexing       创建索引
  --update              如果数据存在，执行更新操作
```

## 整理 POC 目录

将 POC 整理到 '组件类型/组件名' 目录下

```sh
python scripts/utils.py -v --sort --poc-dir CScanPoc/pocs
```

## 更新数据到数据库

```sh
python scripts/utils.py -v \
  --host ... --user ... --db ...  --pass \          # 数据库配置
  --poc-dir CScanPoc/pocs \
  --update # 如果加该参数，对于数据库中已有的数据，进行更新；否则对于已有数据就跳过
```

更新过程是先创建相关元数据数据（indexing）到 `--index-dir`(默认 `index` 下)，然后使用该
元数据对数据库进行更新。

如果执行过程中因为数据库连接发生中断，下次执行时可以添加 `--skip-indexing` 跳过元数据创建这
一步加快执行速度。