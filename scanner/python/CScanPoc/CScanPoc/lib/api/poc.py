# coding: utf-8

from abc import abstractmethod, abstractproperty, ABCMeta
from datetime import datetime
from vuln import ABVuln
from CScanPoc.lib.core.log import CScanOutputer
from CScanPoc.lib.parse.args import create_poc_cmd_parser

argparser = create_poc_cmd_parser()


class ABPoc:
    '''Abstract Base of specific CScan poc

    漏洞的 POC。子类中必须覆写方法 verify 和 exploit
    '''
    __metaclass__ = ABCMeta

    # CScanPoc 内部 POC id
    poc_id = ''

    # POC 名
    poc_name = None

    @property
    def option_schema(self):
        '''定义 POC 所需的执行参数

        JSON-Schema 的一个子集，示例如下

        {
            "required": ["base_path"]             # 必选参数
            "properties": {
                "base_path": {                    # 参数名
                    "type": "string",             # 我们暂时只考虑 string | number | boolean
                    "description": "部署路径",     # 参数描述
                    "$default_ref": {             # 默认值引用指定组件的属性值
                        "component": "Discuzz",   # 组件名，可以为空；为空则组件默认为关联漏洞对应的组件
                        "property": "base_path"   # 我们 POC 该执行参数默认值引用的是 Discuzz 组件的 base_path 属性
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
        '''
        return getattr(self, '_option_schema', {})

    @option_schema.setter
    def option_schema(self, val):
        self._option_schema = val

    # 执行参数：应该满足 option_schema 的定义
    _exec_option = {}

    def _check_and_get_option_schema(self, k):
        property_schemas = self.option_schema.get('properties')
        if property_schemas is None:
            raise Exception('该 POC 不支持该执行参数 {}'.format(k))
        property_schema = property_schemas.get(k)
        if property_schema is None:
            raise Exception('该 POC 不支持该执行参数 {}'.format(k))
        return property_schema

    def get_option(self, k, defaultV=None):
        '''获取执行参数
        
        1. 如果参数设定了，返回设定的参数值
        2. 如果存在 '$default_ref' 尝试返回引用的组件属性值
        3. 如果引用的组件属性值不存在，查看是否存在 'default'， 存在就返回该值
        4. 否则，返回 defaultV
        '''
        property_schema = self._check_and_get_option_schema(k)

        if k in self._exec_option:
            return self._exec_option.get(k)
        else:
            return property_schema.get('default', defaultV)
        # TODO: 如果存在 '$default_ref' 尝试从组件属性中获取该值

    def set_option(self, k, v):
        property_schema = self._check_and_get_option_schema(k)
        typ = property_schema.get('type', 'string')
        if typ == 'string':
            self._exec_option[k] = str(v)
        elif typ == 'boolean':
            try:
                self._exec_option[k] = bool(v)
            except:
                raise Exception(
                    '执行参数 {} 不是 bool [POC 定义该执行参数为 boolean]'.format(v))
        elif typ == 'number':
            try:
                v = int(v)
            except:
                try:
                    v = float(v)
                except:
                    raise Exception(
                        '执行参数 {} 不是 number [POC 定义该执行参数为 number]'.format(v))
            self._exec_option[k] = v
        else:
            raise Exception('POC 定义错误：无效属性类型 {}'.format(typ))

    def get_poc_name(self):
        '''当前 poc 名未指定的话，尝试使用其对应漏洞的名字（针对只扫描一个漏洞的 poc）'''
        if self.poc_name == None or self.poc_name.strip() == '':
            return self.vuln.name
        else:
            return self.poc_name

    @abstractproperty
    def author(self):
        '''poc 作者'''
        pass

    @abstractproperty
    def create_date(self):
        '''poc 创建时间
        返回类似 datetime(2017, 12, 30) 的对象
        '''
        pass

    def __init__(self, vuln=None):
        """ABPoc.__init__

        :param vuln: 可选，当前扫描器关联的漏洞
        :type vuln: CScanPoc.lib.api.vuln.Vuln
        """
        if vuln is None or not isinstance(vuln, ABVuln):
            raise Exception('POC 关联漏洞未正确初始化')
        # 当前 poc 扫描的漏洞
        self.vuln = vuln

        # 漏洞扫描输出
        self.output = CScanOutputer

        # 扫描目标
        self.target = None

    def run(self, target=None, mode='verify'):
        """执行扫描操作

        当 target=None 时，忽略函数参数，解析命令行参数获取执行参数

        :param target: 扫描目标
        :param mode: 扫描模式
        :type target: str, None 默认为 None
        :type mode: 'verify' | 'exploit'
        """
        if target is None:
            args = argparser.parse_args()
            if args.exec_option is not None:
                for opt in args.exec_option:
                    if '=' not in opt:
                        self.set_option(opt, True)
                    else:
                        (k, v) = opt.split('=', 1)
                        self.set_option(k, v)
            self.target = args.url
            mode = args.mode
        else:
            self.target = target

        if not self.target:
            return

        if mode == 'verify':
            self.verify()
        else:
            self.exploit()

    @abstractmethod
    def verify(self):
        pass

    @abstractmethod
    def exploit(self):
        pass

    def __str__(self):
        return '<Poc id={0} name={1}>'.format(self.poc_id, self.poc_name)
