# coding: utf-8
from datetime import datetime
from abc import abstractmethod, abstractproperty, ABCMeta


class ABVuln(object):
    '''漏洞信息定义

    所有漏洞的定义继承自此类，定义漏洞的相关属性。相关抽象属性字段
    （abstractproperty 修饰的）需要被覆盖。
    '''
    __metaclass__ = ABCMeta

    # 平台漏洞 ID
    vuln_id = ''

    # 国家信息安全漏洞共享平台漏洞编号
    cnvd_id = ''

    # 漏洞关联 CVE 编号
    cve_id = ''

    @abstractproperty
    def name(self):
        '''漏洞名称'''
        pass

    @abstractproperty
    def type(self):
        '''漏洞类型

        CScanPoc.lib.core.enums.VulnType
        '''
        pass

    @abstractproperty
    def product(self):
        '''漏洞影响到的应用/组件名称'''
        pass

    @abstractproperty
    def product_version(self):
        '''漏洞影响到的应用/组件版本列表，list'''
        pass

    @abstractproperty
    def level():
        '''漏洞危害级别

        CScanPoc.lib.core.enums.VulnLevel
        '''
        pass

    @abstractproperty
    def disclosure_date(self):
        '''漏洞发布时间'''
        pass

    @abstractproperty
    def desc(self):
        '''漏洞描述利用策略之类的东西'''
        pass

    @abstractproperty
    def ref(self):
        '''漏洞来源，一般是漏洞发布地址'''
        pass

    def __str__(self):
        return '<Vuln id={0} name={1} level={2}>'.format(self.vuln_id, self.name, self.level)
