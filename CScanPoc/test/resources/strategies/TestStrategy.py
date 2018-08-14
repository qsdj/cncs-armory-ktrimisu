# coding: utf-8

import json
from CScanPoc import ABStrategy


class TestStrategy(ABStrategy):

    def __init__(self):
        ABStrategy.__init__(self)
        self.option_schema = {
            'properties': {
                'component': {
                    'type': 'string',
                    'default': 'Unkown'
                }
            }
        }

    @property
    def author(self):
        return 'lotuc'

    @property
    def strategy_id(self):
        return '00000000-0000-STRA-TEGY-000000000000'

    @property
    def name(self):
        return '简单组件扫描策略'

    @property
    def description(self):
        return '此策略在给定组件名后，选定组件相关的所有 POC 对对应资产进行扫描'

    @property
    def poc_ids(self):
        return ['00000000-0000-0000-0POC-000000000000']

    def launch(self):
        self.output.info('开始执行测试策略：%s' % self.name)
        self.output.info('传入的组件属性：')
        for line in json.dumps(
                self.components_properties, indent=2).split('\n'):
            self.output.info(line)
        self.output.info('传入的执行参数：')
        try:
            self.output.info('传入组件：%s' % self.get_option('component'))
        except:
            pass
        for line in json.dumps(
                self.exec_option, indent=2).split('\n'):
            self.output.info(line)
        super().launch()
        self.output.info('测试策略执行结束：%s' % self.name)
