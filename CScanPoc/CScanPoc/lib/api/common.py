# coding: utf-8
from abc import ABCMeta, abstractproperty
from CScanPoc.lib.parse.args import create_poc_cmd_parser, parse_args
from .component import Component
from .schema import ObjectSchema, ValueNotFound
from CScanPoc.lib.core.log import CScanOutputer


class RuntimeOptionSupport(metaclass=ABCMeta):
    '''运行时参数支持

    - 执行参数
    - 组件属性
    '''

    def __init__(self):
        # 执行参数
        self._exec_option = {}
        self._option_schema = {}
        self._option_schema_handle = ObjectSchema({})

        # 组件属性
        self._components_properties = {}

    # ------------------ 组件属性支持 ----------------==
    def set_component_property(self, component_name, key, val):
        '''设定指定组件的属性'''
        if component_name not in self._components_properties:
            self._components_properties[component_name] = {}
        Component.get_component(component_name).property_schema_handle.set_val(
            self._components_properties[component_name], key, val)

    @property
    def components_properties(self):
        '''组件属性 Dict<组件名， Dict<属性名, 属性值>>'''
        return self._components_properties

    @components_properties.setter
    def components_properties(self, val):
        self._components_properties = val

    # ------------------ 执行参数支持 ----------------==
    @abstractproperty
    def default_component(self):
        '''默认组件名'''
        pass

    @property
    def option_schema(self):
        '''定义 POC 所需的执行参数定义

        定义方式见 schema.py
        '''
        return self._option_schema

    @option_schema.setter
    def option_schema(self, val):
        if 'name' not in val:
            val['name'] = '{}-Option Schema'.format(self)
        self._option_schema = val
        self._option_schema_handle = ObjectSchema(val)

    @property
    def option_schema_handle(self):
        '''option_schema 对应 ObjectSchema'''
        return self._option_schema_handle

    def set_option(self, key, val):
        '''设定执行参数'''
        ObjectSchema(self.option_schema).set_val(self._exec_option, key, val)

    @property
    def exec_option(self):
        '''执行参数'''
        return self._exec_option

    @exec_option.setter
    def exec_option(self, val):
        self._exec_option = val

    def get_option(self, key, default=None):
        '''获取执行参数'''
        try:
            return self.option_schema_handle.get_val(
                self.exec_option,
                key,
                component_properties=self.components_properties,
                default_ref_component=self.default_component)
        except ValueNotFound:
            return default

    def parse_args(self, args=None):
        """解析执行参数

        当 target=None 时，忽略函数参数，解析命令行参数获取执行参数

        :param target: 扫描目标
        :param mode: 扫描模式
        :type target: str, None 默认为 None
        :type mode: 'verify' | 'exploit'
        """
        if args is None:
            argparser = create_poc_cmd_parser()
            args = argparser.parse_args()
        if args.json_output:
            CScanOutputer.set_json_output()
        self.target = args.url
        parse_args(args, self.set_option,
                   self.set_component_property,
                   self.default_component)
        return args
