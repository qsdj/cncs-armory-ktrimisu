# coding: utf-8
'''POC/策略运行时支持

- 执行参数定义、解析
- 组件属性参数定义、解析
'''

import argparse
from abc import ABCMeta, abstractproperty
from CScanPoc.lib.core.log import (setup_cscan_outputer,
                                   setup_cscan_poc_logger,
                                   CSCAN_LOGGER as logger)
from .component import Component
from .schema import ObjectSchema, ValueNotFound, SchemaException


def create_cmd_parser():
    '''创建命令行解析器'''
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "-u", "--url", dest="url", required=True,
        help="目标 URL (e.g. \"http://lotuc.org/\")")
    parser.add_argument(
        '--log-level', required=False, default='DEBUG',
        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'SUCCESS', 'REPORT'],
        help="日志级别, default: DEBUG")
    parser.add_argument(
        '--mode', required=False, default="verify", choices=["verify", "exploit"],
        help="POC 执行模式, default: verify")
    parser.add_argument(
        '--index-dir', required=False, dest='index_dir',
        help='POC 索引目录')
    parser.add_argument(
        '--json-output', required=False, dest='json_output',
        action='store_true', default=False,
        help='输出 JSON 格式结果')
    parser.add_argument('-v', dest='verbose', action='store_true',
                        help='系统日志配置')
    parser.add_argument('-vv', dest='very_verbose', action='store_true',
                        help='系统日志配置')
    # 执行参数解析
    parser.add_argument('--exec-option', metavar='KEY=VALUE', type=str, nargs='+',
                        help='执行参数定义')
    # 组件属性定义
    parser.add_argument('--component-property', metavar='COMPONENT.PROPERTY=VALUES',
                        type=str, nargs='+',
                        dest='component_properties',
                        help='组件属性定义')
    return parser


def parse_properties(args,
                     set_option=None,
                     set_component_property=None,
                     default_component=None,
                     exec_options=None,
                     components_properties=None):
    if components_properties is not None:
        def _set_component_property(component_name, key, val):
            if component_name not in components_properties:
                components_properties[component_name] = {}
            Component.get_component(component_name).property_schema_handle.set_val(
                components_properties[component_name], key, val)
        set_component_property = _set_component_property

    '''解析参数中的执行参数和组件属性'''
    if set_option:
        # 执行参数解析
        for opt in args.exec_option or []:
            (key, val) = (opt, True)
            if '=' in opt:
                (key, val) = opt.split('=', 1)
            try:
                set_option(key, val)
            except SchemaException as err:
                logger.warning('执行参数设定错误: %s', err)

    if set_component_property:
        # 组件属性解析
        for opt in args.component_properties or []:
            (key, val) = (opt, True)
            if '=' in opt:
                (key, val) = opt.split('=', 1)
            (component_name, prop) = (default_component, key)
            if '.' in key:
                (component_name, prop) = key.split('.', 1)
            try:
                set_component_property(component_name, prop, val)
                logger.debug('解析设定组件 %s 属性：%s=%s', component_name, prop, val)
            except SchemaException as err:
                logger.warning('组件属性设定错误: %s', err)


class RuntimeOptionSupport(metaclass=ABCMeta):
    '''运行时参数支持

    - 执行参数
    - 组件属性
    '''

    def __init__(self):
        self.target = None
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
            argparser = create_cmd_parser()
            args = argparser.parse_args()
        # 执行目标
        self.target = args.url
        # 日志配置
        setup_cscan_poc_logger(verbose=args.verbose,
                               very_verbose=args.very_verbose)
        setup_cscan_outputer(args.json_output)

        parse_properties(args,
                         self.set_option,
                         self.set_component_property,
                         self.default_component)
        return args
