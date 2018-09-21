# CScanPoc

CScan Poc 开发文档。

## 资产

文档中资产的概念等同于主机（大致等同于 IP/域名）。

## 接口概述

接口集中在 `CScanPoc.lib.api` 中定义。

### 组件：[Component](CScanPoc/lib/api/component.py)

组件是**资产的一类属性**，其类别主要如下：

- 服务级组件
- 服务提供级组件
- 应用类组件
  - os
  - cms
  - middleware
  - ...

组件的具体定义放在[CScanPoc/CScanPoc/resources/component/](CScanPoc/CScanPoc/resources/component/)
下以 `组件名.json` 的方式命名的文件中。其中定义的格式应该是：

```python
{
  "type": "cms",          # cms | os | middleware | database | device | service | service_provider
  "producer": "",         # 厂商
  "desc": "",             # 描述
  "properties": {}        # 此定义和属性定义中 "properties" 的定义一致
}
```

### 漏洞：[ABVuln](CScanPoc/lib/api/vuln.py)

**某个组件**上存在的特定缺陷。

### POC: [ABPoc](CScanPoc/lib/api/poc.py)

漏洞验证程序，验证特定漏洞是否存在的代码，其中可能包含对其的利用代码。

### 策略：[ABStrategy](CScanPoc/lib/api/strategy.py)

对目标资产的一次有计划的可能会相对复杂的扫描。可能利用多个 POC.

### 日志

- `CScanPoc.lib.core.log.CSCAN_LOGGER` 用于记录系统执行日志的 logger。
- `CScanPoc.lib.core.log.get_scan_outputer` 用于创建记录系统扫描输出的 outputer。

## 属性及参数

### 参数

POC 和策略都通过 `option_schema` 属性定义执行参数，其定义方式同属性。

它们存在一些通用参数，定义在了 [CScanPoc.lib.api.common](CScanPoc/lib/api/common.py) 中。
主要有：

- `-u`: 目标地址，即目标资产的 IP/域名。
- `--component-property` / `--component-property-file`: 组件属性，目标资产的组件及对应属性。

### 属性

```python
{
  'name': '',            # Schema 名字
  'description': '',     # Schema 描述
  'properties': {        # 属性定义
    'prop_1': {              # 属性名
      'type': 'string',          # 【可选，默认 'string'】属性类型 'string' | 'number' | 'boolean'
      'description': '',         # 【可选】属性描述
      'default': '',             # 【可选】默认值，类型要和 'type' 中定义的一致
      '$default_ref': {          # 【可选】默认值引用
        'component': '',             # 【可选】默认值引用的组件名
        'property': '',              # 默认值引用的组件属性
      }
    }
  }
}
```

## 开发环境

机器上应该安装有 Python 3. 更新 pip (`pip install -U pip`), 安装 pipenv (`pip install pipenv`)。

```sh
pipenv install --dev .
```

## 命令

### utils.py

- 用于生成 组件、POC、策略等数据索引。
- 用于更新相关数据到数据库。

索引的常用，写成了脚本 `build.sh`，直接运行：

```sh
./build.sh ../pocs ../strategies true
```

更新到数据库：先执行上面的索引操作，然后：

```sh
python scripts/utils.py -v --update --skip-indexing \
    --host 数据库主机 \
    --user 用户名 \
    --db 数据库名 \
    --pass 数据库密码
```

同步漏洞详情(exploit 字段值):

```sh
python scripts/utils.py -v --vuln-detail-dir ../vulns \
    --host 数据库主机 \
    --user 用户名 \
    --db 数据库名 \
    --pass 数据库密码 \
```

### poc_exe.py

根据指定的 POC ID 执行对应 POC.

```sh
pipenv run python scripts/poc_exe.py --poc-id 00000000-0000-0000-0POC-000000000000 -u http://www.baidu.com
```

当然，还可以传入其它参数如组件属性、执行参数：

```sh
pipenv run python scripts/poc_exe.py --poc-id 00000000-0000-0000-0POC-000000000000 -u http://www.baidu.com \
    --component-property LotucTestProduct.deploy_path=/hello \
    --exec-option component=LotucTestProduct
```
> 注意：需要先使用 utils.py 索引

### strategy_exe.py

```sh
pipenv run python scripts/strategy_exe.py --strategy-id 00000000-0000-STRA-TEGY-000000000000 -u http://www.baidu.com
```

同样，可以传入其它参数如组件属性、执行参数：

```sh
pipenv run python scripts/strategy_exe.py --strategy-id 00000000-0000-STRA-TEGY-000000000000 -u http://www.baidu.com \
    --component-property LotucTestProduct.deploy_path=/hello \
    --exec-option component=LotucTestProduct
```

> 注意：需要先使用 utils.py 索引

### recommend_task.py

```sh
python scripts/recommend_task.py --component-property CmsEasy.deploy_path=/

python scripts/recommend_task.py --component-property http.port=80

python scripts/recommend_task.py --component-property http.port=80 IIS.port=80

python scripts/recommend_task.py --component-property http.port=80 IIS.port=80 CmsEasy.deploy_path=/
```
