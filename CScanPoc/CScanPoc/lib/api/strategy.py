# coding: utf-8
'''执行策略'''

from abc import ABCMeta, abstractproperty, abstractmethod
from CScanPoc.lib.utils.indexing import find_poc, INDEX_CONFIG


class ABStrategy(metaclass=ABCMeta):
    '''策略'''

    def __init__(self, index_dir=INDEX_CONFIG.index_dir):
        '''
        :param index_dir: POC 索引目录
        '''
        self.index_dir = index_dir

    def get_poc(self, poc_id):
        '''根据 poc_id 获取 POC

        注意每次执行获取将得到一个新的实例
        '''
        return find_poc(poc_id, self.index_dir)

    @abstractproperty
    def name(self):
        '''策略名'''
        pass

    @abstractproperty
    def pocs(self):
        '''使用到的 POC ID 列表'''
        pass

    def run(self, target=None, exec_option={}, components_properties={}, args=None):
        '''执行策略

        :param index_dir: POC 索引目录
        '''
        if target is None:
            if args is None:
                argparser = create_poc_cmd_parser()
                args = argparser.parse_args()
            mode = args.mode
            self.target = args.url
            parse_args(args, self.set_option,
                       self.set_component_property, self.vuln.product)
        else:
            self.target = target
            self.exec_option = exec_option
            self.components_properties = components_properties

    def launch(self):
        pass
