# coding: utf-8

import datetime
from unittest.mock import patch, PropertyMock
import pytest
from CScanPoc.lib.api.component import Component
from CScanPoc.lib.api.vuln import ABVuln, VulnLevel, VulnType
from CScanPoc.lib.api.poc import ABPoc


def test_vuln_definition():
    with pytest.raises(TypeError, message='没有定义必要属性'):
        class Vuln(ABVuln):
            pass
        vuln = Vuln()

    class Vuln(ABVuln):
        disclosure_date = datetime.datetime.now()
        level = 'a'
        name = 'vuln0'
        product = 'CmsEasy'
        product_version = '1.0'
        ref = 'ref0'
        type = 'typ0'
        desc = 'desc0'

    vuln = Vuln()
    assert len(vuln.check()) != 0


class Vuln0(ABVuln):
    '''测试漏洞0'''
    name = 'vuln0'
    disclosure_date = datetime.datetime.now()
    type = VulnType.FILE_UPLOAD
    level = VulnLevel.LOW
    product = 'component0'
    product_version = ['1.0']
    ref = 'ref0'
    desc = 'desc0'


component0_schema = {'name': 'component0', 'properties': {
    'prop0': {'default': 'pro0 in component1'}
}}
component1_schema = {'name': 'component1', 'properties': {
    'prop1': {'default': 'pro1 in component1'}
}}


class Poc0(ABPoc):
    author = 'lotuc'
    create_date = datetime.datetime.now()

    def __init__(self):
        super(Poc0, self).__init__(Vuln0())
        self.option_schema = {'properties': {
            'opt1': {'default': 'default_opt1'},
            'opt2': {'$default_ref': {'property': 'prop0'}},
            'opt3': {'$default_ref': {'component': 'component1', 'property': 'prop1'}}
        }}

    def verify(self):
        self.output.info('Starting...')
        self.output.info('Sending Payload 1...')
        self.output.info('Sending Payload 2...')
        self.output.warning('Found something...')
        self.output.info('Double checking...')
        self.output.report(self.vuln, 'confirmed because of...')


def test_poc_definition():
    with pytest.raises(TypeError, message='没有定义必要属性'):
        class Poc(ABPoc):
            pass
        poc = Poc()

    with pytest.raises(TypeError, message='没有定义关联漏洞', match='.*missing.*vuln.*'):
        class Poc(ABPoc):
            author = 'lotuc'
            create_date = datetime.datetime.now()

            def verify(self):
                pass

        poc = Poc()

    # 正确的 POC 定义
    poc0 = Poc0()


def test_poc_execution():
    poc0 = Poc0()
    poc0.run('http://www.baidu.com', exec_option={},
             components_properties={'component1': {'prop1': 'hello world'}})
    assert poc0.get_option('opt1') == 'default_opt1'

    with patch.object(Component, 'property_schema', new_callable=PropertyMock,
                      return_value=component0_schema):
        # 返回执行参数引用组件的默认值
        assert poc0.get_option(
            'opt2') == component0_schema['properties']['prop0']['default']

    with patch.object(Component, 'property_schema', new_callable=PropertyMock,
                      return_value=component1_schema):
        # 返回执行参数引用组件的属性
        assert poc0.get_option('opt3') == 'hello world'
