# coding: utf-8

import os
import json
from enum import Enum
from pkg_resources import resource_filename, resource_exists

COMPONENT_RESOURCE_MODULE = 'CScanPoc.resources.component'
COMMON_COMPONENT_RESOURCE_MODULE = COMPONENT_RESOURCE_MODULE + '.common'
COMPONENT_META_FILENAME = '__meta__.json'


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

    __component_meta = None
    __component_cache = {}

    @staticmethod
    def get_component(name):
        '''获取组件信息'''
        if name not in Component.__component_cache:
            Component.__component_cache[name] = Component(name)
        return Component.__component_cache[name]

    @staticmethod
    def get_common_components():
        '''通用组件'''
        try:
            common_pth = resource_filename(
                COMMON_COMPONENT_RESOURCE_MODULE, '')
            return map(lambda filename: filename[:-5],
                       filter(lambda filename:
                              filename.endswith('.json')
                              and filename != '__meta__.json',
                              os.listdir(common_pth)))
        except:
            return []

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
        self._load_meta()

    def _load(self):
        '''加载组件信息'''
        filename = self._name + '.json'
        try:
            pth = None
            if resource_exists(COMPONENT_RESOURCE_MODULE, filename):
                pth = resource_filename(COMPONENT_RESOURCE_MODULE, filename)
            if resource_exists(COMMON_COMPONENT_RESOURCE_MODULE, filename):
                pth = resource_filename(
                    COMMON_COMPONENT_RESOURCE_MODULE, filename)

            if pth is not None:
                self._info = json.load(open(pth))
            else:
                self.__warn_once(
                    self.name,
                    ('组件[name={}]定义文件不存在，组件信息将使用默认值：'
                     '可以在模块 {}  或 {} 下创建 {} 文件定义').format(
                         self.name,
                         COMPONENT_RESOURCE_MODULE,
                         COMMON_COMPONENT_RESOURCE_MODULE,
                         filename))
        except Exception as err:
            self.__warn_once(self.name,
                             '组件[name={}]定义加载出错({})：{}'.format(
                                 self.name, pth, err))

    def _load_meta(self):
        if Component.__component_meta is not None:
            return
        try:
            if resource_exists(COMMON_COMPONENT_RESOURCE_MODULE, COMPONENT_META_FILENAME):
                pth = resource_filename(
                    COMMON_COMPONENT_RESOURCE_MODULE, COMPONENT_META_FILENAME)
                Component.__component_meta = json.load(open(pth))
            else:
                self.__warn_once('__meta__', '组件元定义加载失败')
        except Exception as err:
            self.__warn_once('__meta__', '组件元定义加载失败({})'.format(err))

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
        # 组件定义文件中定义的属性
        properties = self._info.get('properties', {})

        for component in self.parent_components:
            if component.name == self.name:
                continue
            parent_properties = component.property_schema.get('properties')
            for prop in parent_properties:
                if prop not in properties:
                    properties[prop] = parent_properties[prop]

        return {
            'name': self.name,
            'properties': properties
        }

    @property
    def property_schema_handle(self):
        '''property_schema 对应的 ObjectSchema'''
        from .schema import ObjectSchema
        return ObjectSchema(self.property_schema)

    @property
    def parent_components(self):
        # 组件定义文件中定义的父组件
        from ..core.log import CSCAN_LOGGER as logger
        derive_from = self._info.get('derive_from', [])
        if derive_from:
            logger.debug('组件 %s derive_from: %s', self.name, derive_from)

        for derivation_def in (Component.__component_meta or {}).get('derivation', []):
            if 'match' not in derivation_def:
                continue
            match = derivation_def['match']
            if 'type' not in match and 'name' not in match:
                continue

            # 我们为每个类型创建了该类型名的通用组件，所以这里匹配到名字等于类型时
            # 是匹配到了这类通用组件，不能继承自身属性（递归了）
            # TODO: 这里没有检查环形引用，有可能导致死循环，暂不做处理，定义时注意
            if (match.get('type')
                and match.get('type') == self.type.name
                and match.get('type') != self.name) \
               or (match.get('name')
                   and match.get('name') == self.name):
                logger.debug('组件 %s 匹配 %s: derive_from %s',
                             self.name, match, derivation_def['derive_from'])
                derive_from.extend(derivation_def['derive_from'])

        return [Component.get_component(name) for name in set(derive_from)]
