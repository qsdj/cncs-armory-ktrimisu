# coding: utf-8

import json
from enum import Enum
from pkg_resources import resource_filename, resource_exists

COMPONENT_RESOURCE_MODULE = 'CScanPoc.resources.component'


class ComponentType(Enum):
    '''组件类型'''
    others = 0
    cms = 1
    os = 2
    middleware = 3
    database = 4
    device = 5
    service = 6
    service_provider = 7


class Component:
    '''组件'''

    __component_cache = {}

    @staticmethod
    def get_component(name):
        '''获取组件信息'''
        if name not in Component.__component_cache:
            Component.__component_cache[name] = Component(name)
        return Component.__component_cache[name]

    def __warn_once(self, k, msg):
        if self.__warned.get(k):
            return
        self.__warned[k] = True
        from ..core.log import CSCAN_LOGGER as logger
        logger.warning(msg)

    def __init__(self, name):
        '''组件信息

        :param name: 组件名
        :param info_dir: 组件信息存放目录，按名字索引
        '''
        self._name = name
        self._info = {}
        self.__warned = {}
        self._load()

    def _load(self):
        '''加载组件信息'''
        filename = self._name + '.json'
        try:
            pth = None
            if resource_exists(COMPONENT_RESOURCE_MODULE, filename):
                pth = resource_filename(COMPONENT_RESOURCE_MODULE, filename)
                self._info = json.load(open(pth))
            else:
                self.__warn_once(self.name,
                                 '组件[name={}]定义文件不存在 {}，组件信息将使用默认值'.format(
                                     self.name, pth))
        except Exception as err:
            self.__warn_once(self.name,
                             '组件[name={}]定义加载出错({})：{}'.format(
                                 self.name, pth, err))

    @property
    def name(self) -> str:
        '''组件名'''
        return self._name

    @property
    def type(self) -> ComponentType:
        '''组件类型'''
        try:
            return ComponentType[self._info.get('type', 'others')]
        except KeyError as err:
            self.__warn_once(
                '{}-type'.format(self.name),
                '组件[name={}]类型未知: {}'.format(self.name, err))
            return ComponentType.others

    @property
    def producer(self):
        '''组件产商'''
        return self._info.get('producer', None)

    @property
    def description(self):
        '''组件描述'''
        return self._info.get('desc', None)

    @property
    def property_schema(self):
        '''属性定义'''
        schema = {
            'name': self.name,
            'properties': self._info.get('properties', {})
        }
        if self.type in (ComponentType.cms, ComponentType.middleware):
            if 'deploy_path' not in schema['properties']:
                schema['properties']['deploy_path'] = {
                    'type': 'string',
                    'default': '/'
                }
        return schema

    @property
    def property_schema_handle(self):
        '''property_schema 对应的 ObjectSchema'''
        from .schema import ObjectSchema
        return ObjectSchema(self.property_schema)
