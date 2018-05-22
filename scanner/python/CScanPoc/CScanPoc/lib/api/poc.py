# coding: utf-8

from abc import abstractmethod, abstractproperty, ABCMeta
from datetime import datetime
from CScanPoc.lib.core.log import CScanOutputer
from CScanPoc.lib.parse.args import create_poc_cmd_parser

argparser = create_poc_cmd_parser()

class ABPoc:
    '''Abstract Base of specific CScan poc

    漏洞的 POC。子类中必须覆写方法 verify 和 exploit
    '''
    __metaclass__ = ABCMeta

    # CScanPoc 内部 POC id
    poc_id = ''

    # POC 名
    poc_name = None

    def get_poc_name(self):
        '''当前 poc 名未指定的话，尝试使用其对应漏洞的名字（针对只扫描一个漏洞的 poc）'''
        if self.poc_name == None or self.poc_name.strip() == '':
            return self.vuln.name
        else:
            return self.poc_name

    @abstractproperty
    def author(self):
        '''poc 作者'''
        pass

    @abstractproperty
    def create_date(self):
        '''poc 创建时间
        返回类似 datetime(2017, 12, 30) 的对象
        '''
        pass

    def __init__(self, vuln=None):
        """ABPoc.__init__

        :param vuln: 可选，当前扫描器关联的漏洞
        :type vuln: CScanPoc.lib.api.vuln.Vuln
        """
        # 当前 poc 扫描的漏洞
        self.vuln = vuln

        # 漏洞扫描输出
        self.output = CScanOutputer

        # 扫描目标
        self.target = None

    def run(self, target=None, mode='verify'):
        """执行扫描操作

        当 target=None 时，忽略函数参数，解析命令行参数获取执行参数

        :param target: 扫描目标
        :param mode: 扫描模式
        :type target: str, None 默认为 None
        :type mode: 'verify' | 'exploit'
        """
        if target is None:
            args = argparser.parse_args()
            self.target = args.url
            mode = args.mode
        else:
            self.target = target

        if not self.target:
            return

        if mode == 'verify':
            self.verify()
        else:
            self.exploit()

    @abstractmethod
    def verify(self):
        pass

    @abstractmethod
    def exploit(self):
        pass
