# coding: utf-8

from unittest.mock import patch, PropertyMock
import pytest
from CScanPoc.lib.api.component import Component
from CScanPoc.lib.api.schema import ObjectSchema, SchemaException, ValueNotFound, PropertyNotFound

schema = ObjectSchema({
    'name': '测试 Schema',
    'properties': {
        'prop0': {},
        'prop1': {'type': 'string'},
        'prop2': {'type': 'string', 'default': 'prop2_val'},
        'prop3': {'type': 'number'},
        'prop4': {'type': 'string', '$default_ref': {'property': 'deploy_path'}},
        'prop5': {'type': 'string', '$default_ref': {'component': 'CmsEasy',
                                                     'property': 'deploy_path'}}
    }
})

val = {'prop0': 'hello', 'prop1': 'world'}


def test_get_property_schema():
    assert schema.get_property_schema('prop0') == {}
    assert schema.get_property_schema('prop1') == {'type': 'string'}


def test_get_val():
    assert schema.get_val(val, 'prop0') == 'hello'
    assert schema.get_val(val, 'prop1') == 'world'

    # 默认值 'default'
    assert schema.get_val(val, 'prop2') == 'prop2_val'

    fake_cms_easy_schema = {'name': 'FakeCmsEasySchema',
                            'properties': {'deploy_path': {'default': 'fake_val'}}}
    fake_cms_easy_schema_no_properties = {'name': 'FakeCmsEasySchema'}

    with patch.object(Component, 'property_schema', new_callable=PropertyMock,
                      return_value=fake_cms_easy_schema):
        # 默认值引用 '$default_ref'
        # 这里使用参数定义引用 CmsEasy 组件
        assert schema.get_val(
            val, 'prop4', default_ref_component='CmsEasy') == 'fake_val'
        # prop5 中已经定义了引用 CmsEasy 组件
        assert schema.get_val(val, 'prop5') == 'fake_val'

    with patch.object(Component, 'property_schema', new_callable=PropertyMock,
                      return_value=fake_cms_easy_schema_no_properties):
        # 引用的组件属性不存在
        with pytest.raises(PropertyNotFound):
            assert schema.get_val(
                val, 'prop4', default_ref_component='CmsEasy') == '/'

    # 无默认值
    with pytest.raises(ValueNotFound, message='无默认值，抛出异常'):
        schema.get_val({}, 'prop0')


def test_set_val():
    test_val = {}
    with pytest.raises(PropertyNotFound):
        schema.set_val(test_val, 'fuck', 10)

    # 类型错误（且不能转换到目标类型）
    with pytest.raises(SchemaException):
        schema.set_val(test_val, 'prop3', 'hello')

    # 设定为定义属性
    with pytest.raises(PropertyNotFound):
        schema.set_val(test_val, 'random_fjadskl', 'hello')

    # 类型自动转换
    schema.set_val(test_val, 'prop1', 2)
    assert schema.get_val(test_val, 'prop1') == '2'
    schema.set_val(test_val, 'prop1', True)
    assert schema.get_val(test_val, 'prop1') == 'True'
