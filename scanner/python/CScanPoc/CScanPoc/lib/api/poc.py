# coding: utf-8

from abc import abstractmethod, abstractproperty, ABCMeta
from datetime import datetime
from vuln import ABVuln
from CScanPoc.lib.core.log import CScanOutputer
from CScanPoc.lib.parse.args import create_poc_cmd_parser
from CScanPoc.lib.utils.schema_utils import set_dict_value_with_schema_check
from CScanPoc.lib.constants.product_type import get_product_property_schema

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

    # 组件属性
    _components_properties = {}

    def _check_and_get_option_schema(self, k):
        property_schemas = self.option_schema.get('properties')
        if property_schemas is None:
            raise Exception('该 POC 不支持该执行参数 {}'.format(k))
        property_schema = property_schemas.get(k)
        if property_schema is None:
            raise Exception('该 POC 不支持该执行参数 {}'.format(k))
        return property_schema

    def get_component_property(self, name, prop, defaultV=None):
        '''获取指定组件的属性

        :param name: 组件名
        :param property: 属性名
        '''
        properties_schema = get_product_property_schema(name)
        if prop not in properties_schema:
            raise Exception('组件属性未定义 {} {}'.format(name, prop))
        property_schema = properties_schema.get(prop, {})
        properties = self._components_properties.get(name, {})

        if prop not in properties and 'default' not in property_schema:
            return defaultV
        else:
            if prop in properties:
                return properties[prop]
            else:
                return properties_schema['default']

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

        if '$default_ref' in property_schema:
            # 如果存在 '$default_ref' 尝试从组件属性中获取该值
            ref_component = property_schema['$default_ref']
            return self.get_component_property(
                ref_component.get('component', self.vuln.product),
                ref_component['property'],
                property_schema.get('default', defaultV))

        if 'default' in property_schema:
            return property_schema.get('default', defaultV)

    def set_option(self, k, v):
        property_schema = self._check_and_get_option_schema(k)
        set_dict_value_with_schema_check(
            self._exec_option, k, v, property_schema, '执行参数定义')

    def set_component_property(self, component_name, k, v):
        if component_name not in self._components_properties:
            self._components_properties[component_name] = {}
        set_dict_value_with_schema_check(
            self._components_properties[component_name],
            k,
            v,
            get_product_property_schema(
                component_name),
            '组件 {} 属性定义'.format(component_name))

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

    def _parse_args(self, args):

        self.target = args.url
        for opt in args.exec_option or []:
            (k, v) = (opt, True)
            if '=' in opt:
                (k, v) = opt.split('=', 1)
            self.set_option(k, v)

        for opt in args.component_properties or []:
            (k, v) = (opt, True)
            if '=' in opt:
                (k, v) = opt.split('=', 1)

            (component_name, prop) = (self.vuln.product, k)
            if '.' in k:
                (component_name, prop) = k.split('.', 1)

            self.set_component_property(component_name, prop, v)

    def run(self, target=None, mode='verify', exec_option={}, components_properties={}):
        """执行扫描操作

        当 target=None 时，忽略函数参数，解析命令行参数获取执行参数

        :param target: 扫描目标
        :param mode: 扫描模式
        :type target: str, None 默认为 None
        :type mode: 'verify' | 'exploit'
        """
        if target is None:
            args = argparser.parse_args()
            mode = args.mode
            self._parse_args(args)
        else:
            self.target = target
            self._exec_option = exec_option
            self._components_properties = components_properties

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
