# Docker 镜像

项目根目录

`docker build -t cscanpoc -f ./Dockerfile-bundle  .`

执行如下命令获取 `poc_id` -> `POC_MODULE` 的映射（JSON 文件）

`pipenv run python scripts/indexing.py CScanPoc/pocs <输出JSON文件>`

执行 POC:

`docker run -e POC_MODULE=<对应上面脚本获取 POC_MODULE> -e POC_ARGS='-u http://www.shit.com' --rm cscanpoc`

例如

`docker run -e POC_MODULE=CScanPoc.pocs.info_webinf -e POC_ARGS='-u http://www.baidu.com' --rm cscanpoc`

# 同步

可以执行 `pipenv run python scripts/sync.py uuid` 生成一个 UUID 供使用

## 同步单个漏洞（Vuln）到数据库

插入 `CScanPoc/pocs/WordPress_0004.py` 中 Vuln 定义的漏洞（注意 `--vuln_name` 参数），该类的 vuln_id 为空的话则插入不了

`pipenv run python scripts/sync.py vuln --host rm-bp1917k62kyd0f29u5o.mysql.rds.aliyuncs.com --user root --db cscan --pass CScanConfig1314 --vuln_name WordPress_0004.Vuln --insert`

将上面命令中 `--insert` 改成 `--update` 将更新对应 Vuln 的漏洞（根据漏洞 id 去更新）
`pipenv run python scripts/sync.py vuln --host rm-bp1917k62kyd0f29u5o.mysql.rds.aliyuncs.com --user root --db cscan --pass CScanConfig1314 --vuln_name WordPress_0004.Vuln --update`

## 同步单个 poc 到数据库

插入 `CScanPoc/pocs/WordPress_0004.py` 中 Poc 定义的 poc（注意 `--poc_name` 参数），该类的 poc_id 为空的话则插入不了
`pipenv run python scripts/sync.py poc --host rm-bp1917k62kyd0f29u5o.mysql.rds.aliyuncs.com --user root --db cscan --pass CScanConfig1314 --poc_name WordPress_0004.Poc --insert`

同样，将上面的 `--insert` 替换成 `--update` 则根据 poc_id 更新 poc 信息

## 同步所有 poc/vuln 到数据库

更新/插入：默认插入
- `--update` : 更新数据库中对应信息
- `--insert` : 插入信息到数据库

处理 poc/vuln : 默认两个都处理
- `--poc-only` : 只处理 poc
- `--vuln-only` : 只处理 vuln

下面这条语句指定了 `--update` 和 `--poc-only` ：所以意思是更新所有 poc 信息
`pipenv run python scripts/sync.py all --host rm-bp1917k62kyd0f29u5o.mysql.rds.aliyuncs.com --user root --db cscan --pass CScanConfig1314 --poc-dir CScanPoc/pocs --update --poc-only`

类似的，要插入所有 poc 和 vuln 到数据库：
`pipenv run python scripts/sync.py all --host rm-bp1917k62kyd0f29u5o.mysql.rds.aliyuncs.com --user root --db cscan --pass CScanConfig1314 --poc-dir CScanPoc/pocs --insert`
