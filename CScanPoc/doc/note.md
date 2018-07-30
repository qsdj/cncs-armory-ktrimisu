# 一些说明

## POC 参数定义

继承 [ABPoc](../CScanPoc/lib/api/poc.py) 实现 POC 时，可以通过 `option_schema` 指定其所需执行参数，例如

```python
class Poc(ABPoc):
    # ...

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '/',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    # ...

class Vuln:
    # ...
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '6.0'  # 漏洞应用版本
```

这里定义了一个执行参数 `base_path`, 类型为 `string`, 默认值为 `'/'`, 在系统中被调度时，该值可以取
自组件 `Discuz!` 的 `deploy_path` 属性。

`option_schema` 的数据说明：

```json
{
  "required": ["base_path"]             # [可填] 必选参数
  "properties": {
      "base_path": {                    # 参数名
          "type": "string",             # [必填] 我们暂时只考虑 string | number | boolean
          "description": "部署路径",     # [可填] 参数描述
          "$default_ref": {             # [可填] 默认值引用指定组件的属性值
              "component": "Discuz!",   # [可填] 组件名，可以为空；为空则组件默认为关联漏洞对应的组件
              "property": "deploy_path" # [必填] 我们 POC 该执行参数默认值引用的是 Discuz 组件的 base_path 属性
          }
      },
      "retries": {
          "type": "number",
          "default": 3,               # 直接给定默认值
          "description": "请求重试次数"
      },
      "option_3": {
          "type": "string",
          "description": "....",
          "default": "hello world",     # default 和 default_ref 同时存在；如果 ref 的值存在使用它，否则才使用这里的默认值
          "$default_ref": {
              "property": "property_1"
          }
      },
      "option_4": {
          "type": "boolean",
          "description": "...."
      }
  }
}
```

## 组件定义

组件信息可以在 [product_type.py#PRODUCT_INFO](../CScanPoc/lib/constants/product_type.py) 中定义，包含字段

- `type`: [可选] 组件类型，值为 `ProductType`, 如果不填，默认为 `ProductType.others`
- `producer`: [可选] 提供商
- `desc`: [可选] 描述
- `properties`: [可选] 该定义和 [POC 参数定义](#) 中的 `properties` 的定义类似（除了不可以有 `$default_ref` 以外都一样）

例如，添加 `Discuz!` 的定义：

```python
PRODUCT_INFO = {
    # ...
    "Discuz!": {
        "type": ProductType.cms,
        "producer": "北京康盛新创科技有限责任公司",
        "desc": "Crossday Discuz! Board 论坛系统（简称 Discuz! 论坛）是一个采用 PHP 和 MySQL 等其他多种数据库构建的高效论坛解决方案 Discuz! 在代码质量，运行效率，负载能力，安全等级，功能可操控性和权限严密性等方面都在广大用户中有良好的口碑。"
        "properties": {
          "deploy_path": {
            "type": "string",
            "default": "/"
          }
        }
    },  
    # ...
}
```