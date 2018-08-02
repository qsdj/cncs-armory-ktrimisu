# coding: utf-8

from CScanPoc import ABStrategy
from CScanPoc.lib.core.log import CSCAN_LOGGER as logger


class TestStrategy(ABStrategy):

    def __init__(self):
        ABStrategy.__init__(self)

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
        self.output.info('执行传入的属性：%s' % self.components_properties)
        super().launch()
        self.output.info('测试策略执行结束：%s' % self.name)
