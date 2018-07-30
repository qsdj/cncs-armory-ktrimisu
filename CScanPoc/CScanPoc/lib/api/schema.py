# coding: utf-8

from .component import Component


class SchemaException(Exception):
    pass


class PropertyNotFound(SchemaException):
    pass


class ValueNotFound(SchemaException):
    pass


class ObjectSchema:
    '''暂时只考虑如下格式定义

    {
      'name': '',          # Schema 名字
      'description': '',   # Schema 描述
      'properties': {      # 属性定义
        'prop_1': {           # 属性名
          'type': 'string',   # 【可选，默认 'string'】属性类型 'string' | 'number' | 'boolean'
          'description': '',  # 【可选】属性描述
          'default': '',      # 【可选】默认值，类型要和 'type' 中定义的一致
          '$default_ref': {   # 【可选】默认值引用
            'component': '',    # 【可选】默认值引用的组件名
            'property': '',     # 默认值引用的组件属性
          }
        }
      }
    }
    '''

    def __init__(self, schema_dict):
        self._schema = schema_dict

    def get_property_schema(self, prop_name):
        '''获取指定属性的定义'''
        if prop_name not in self._schema.get('properties', {}):
            raise PropertyNotFound(
                '{} property not found: {}'.format(self, prop_name))
        return self._schema['properties'][prop_name]

    def set_val(self, d, k, v):
        '''设定字典值，该字典满足本 Schema 定义，使用 Schema 校验类型

        :param d: 满足本 Schema 的字典
        :param k: 键
        :param v: 值
        '''
        schema = self.get_property_schema(k)
        typ = schema.get('type', 'string')

        if typ == 'string':
            d[k] = str(v)
        elif typ == 'number':
            try:
                d[k] = self.__to_number(v)
            except:
                raise SchemaException(
                    '属性 {} 不满足 {} 定义，类型应该为 {}, 欲设定的值为 {}'.format(
                        k, self, typ, v))
        elif typ == 'boolean':
            d[k] = bool(v)
        else:
            raise SchemaException(
                '{} 属性 {} 类型未知: {}'.format(self, k, typ))

    def get_val(self, d, k, component_properties={}, default_ref_component=None):
        '''获取字典中指定 key 的值，该字典满足本 Schema 定义

        :param d: 满足当前 Schema 的字典
        :param k: 要获取的 key
        :param component_properties: 组件属性, Dict[str, Dict]
        :param default_ref_component: 默认引用的组件名
        :raise ValueNotFound: 值未找到
        '''
        return self._get_val(d, k, component_properties, default_ref_component)

    def _get_val(self, d, k, component_properties={}, default_ref_component=None, depth=10):
        if depth == 0:
            raise ValueNotFound('{}: exceeds max ref depth'.format(depth))
        property_schema = self.get_property_schema(k)
        if k in d:
            return d[k]
        property_ref = property_schema.get('$default_ref', None)
        if property_ref is not None:
            # 首先查找引用的属性的值
            ref_component = property_ref.get(
                'component', default_ref_component)
            if ref_component is None:
                raise SchemaException('{} 属性 {} 默认值引用未指定组件'.format(self, k))
            component = Component.get_component(ref_component)
            try:
                return ObjectSchema(component.property_schema)._get_val(
                    component_properties.get(ref_component, {}),
                    property_ref.get('property'),
                    component_properties,
                    depth-1)
            except ValueNotFound:
                pass
        if 'default' in property_schema:
            # 返回默认值
            return property_schema['default']
        raise ValueNotFound(k)

    def __to_number(self, n):
        if isinstance(n, (int, float)):
            return n
        try:
            return int(n)
        except:
            return float(n)

    def __str__(self):
        return '<Schema {}>'.format(self._schema.get('name', ''))
