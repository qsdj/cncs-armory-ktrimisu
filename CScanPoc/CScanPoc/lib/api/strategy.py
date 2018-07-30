# coding: utf-8
'''执行策略'''

from abc import abstractproperty
from CScanPoc.lib.utils.indexing import find_poc
from .common import RuntimeOptionSupport


class ABStrategy(RuntimeOptionSupport):
    '''策略'''

    def __init__(self):
        '''
        :param index_dir: POC 索引目录
        '''
        RuntimeOptionSupport.__init__(self)
        self._index_dir = None
        self.target = None

    def get_poc(self, poc_id):
        '''根据 poc_id 获取 POC

        注意每次执行获取将得到一个新的实例
        '''
        return find_poc(poc_id, self.index_dir)

    @property
    def index_dir(self):
        '''POC 索引目录'''
        return self._index_dir

    @index_dir.setter
    def index_dir(self, val):
        self._index_dir = val

    @abstractproperty
    def name(self):
        '''策略名'''
        pass

    @property
    def poc_ids(self):
        '''使用到的 POC ID，此属性和 pocs 属性至少有一个被覆盖'''
        poc_ids = []
        for poc in self.pocs:
            poc_ids.append(poc.poc_id)
        return poc_ids

    @property
    def pocs(self):
        '''ABPoc 迭代器，此属性和 poc_ids 属性至少有一个被覆盖'''
        for poc_id in self.poc_ids:
            try:
                yield self.get_poc(poc_id)
            except:
                continue

    @property
    def default_component(self):
        return None

    def run(self, target=None, exec_option={}, components_properties={}, args=None):
        '''执行策略

        :param index_dir: POC 索引目录
        '''

    def run(self, target=None, mode='verify', exec_option={}, components_properties={}, args=None):
        """执行扫描操作

        当 target=None 时，忽略函数参数，解析命令行参数获取执行参数

        :param target: 扫描目标
        :param mode: 扫描模式
        :type target: str, None 默认为 None
        :type mode: 'verify' | 'exploit'
        """

        if target is None:
            args = super().parse_args(args)
            self.target = args.url
            self.index_dir = args.index_dir
            mode = args.mode
        else:
            self.target = target
            self.exec_option = exec_option
            self.components_properties = components_properties

        if not self.target:
            return

        self.launch()

    def launch(self):
        '''默认按序执行所有 POC'''
        for poc in self.pocs:
            try:
                poc.run(self.target,
                        exec_option=self.exec_option,
                        components_properties=self.components_properties)
            except:
                continue
