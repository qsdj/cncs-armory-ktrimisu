# coding: utf-8

from CScanPoc import ABStrategy
from CScanPoc.lib.utils.indexing import iter_pocs_of_component
from CScanPoc.lib.core.log import CSCAN_LOGGER as logger


class HttpScanStrategy(ABStrategy):
    '''组件 POC 按序扫描策略'''

    def __init__(self, component_name=None):
        ABStrategy.__init__(self)
        self.component_name = component_name

    @property
    def author(self):
        return 'hyhm2n'

    @property
    def strategy_id(self):
        return 'HttpScanStrategy'

    @property
    def name(self):
        return 'http策略扫描'

    @property
    def description(self):
        return '此策略在给定组件名后，选定组件相关的所有 POC 对对应资产进行扫描'

    @property
    def pocs(self):
        if self.component_name is None:
            return []
        logger.info('遍历查找组件 %s 的 POC', self.component_name)

        all_http_name = ["Apache", "Nginx", "IIS", "uWSGI", "Tomcat", "Node.js"]
        if (not self.component_name.upper() == "http".upper()) and self.component_name.upper() in [tmp.upper() for tmp in all_http_name]:
            for poc in iter_pocs_of_component(self.component_name, self.index_dir):
                poc.output.strategy = self
                yield poc
        elif self.component_name.upper() == "http".upper():
            for component_name in all_http_name:
                for poc in iter_pocs_of_component(component_name, self.index_dir):
                    poc.output.strategy = self
                    yield poc


if __name__ == '__main__':
    HttpScanStrategy('Apache').run()