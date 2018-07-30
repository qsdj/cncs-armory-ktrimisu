# coding: utf-8
from enum import Enum
from datetime import datetime
from abc import abstractproperty, ABCMeta
from .component import Component


class VulnType(Enum):
    '''漏洞类型'''
    OTHER = 0  # 其他
    INJECTION = 1  # 注入
    XSS = 2  # xss跨站脚本攻击
    XXE = 3  # xml外部实体攻击
    FILE_UPLOAD = 4  # 任意文件上传
    FILE_OPERATION = 5  # 任意文件操作
    FILE_DOWNLOAD = 6  # 意文件下载
    FILE_TRAVERSAL = 7  # 目录遍历
    RCE = 8  # 远程命令/代码执行
    LFI = 9  # 本地文件包含
    RFI = 10  # 远程文件包含
    INFO_LEAK = 11  # 信息泄漏
    MISCONFIGURATION = 12  # 错误配置


class VulnLevel(Enum):
    '''漏洞危害等级'''
    LOW = 1  # 低
    MED = 2  # 中
    HIGH = 3  # 高
    SEVERITY = 4  # 严重


class ABVuln(metaclass=ABCMeta):
    '''漏洞信息定义

    所有漏洞的定义继承自此类，定义漏洞的相关属性。相关抽象属性字段
    （abstractproperty 修饰的）需要被覆盖。
    '''

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

        VulnType
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
    def level(self):
        '''漏洞危害级别

        VulnLevel
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

    @property
    def component(self):
        '''返回组件信息'''
        return Component.get_component(self.product)

    def check(self):
        '''检查字段属性'''
        err_msgs = []
        if self.vuln_id is None or self.vuln_id.strip() == '':
            err_msgs.append('漏洞 ID 为空')
        if not isinstance(self.name, str):
            err_msgs.append('漏洞名不是字符串: {}'.format(self.name))
        if not isinstance(self.type, VulnType):
            err_msgs.append('漏洞类型不是 VulnType: {}'.format(self.type))
        if not isinstance(self.product, str):
            err_msgs.append('漏洞组件不是字符串: {}'.format(self.product))
        if not isinstance(self.product_version, list):
            err_msgs.append('漏洞组件不是列表: {}'.format(self.product_version))
        if not isinstance(self.level, VulnLevel):
            err_msgs.append('漏洞组件不是 VulnLevel: {}'.format(self.level))
        if not isinstance(self.disclosure_date, datetime):
            err_msgs.append(
                '漏洞发现时间不是 datetime.datetime: {}'.format(self.disclosure_date))
        if not isinstance(self.desc, str):
            err_msgs.append('漏洞描述不是字符串: {}'.format(self.desc))
        if not isinstance(self.ref, str):
            err_msgs.append('漏洞引用资料不是字符串: {}'.format(self.ref))
        return err_msgs

    def __str__(self):
        return '<Vuln id={0} name={1} level={2}>'.format(self.vuln_id, self.name, self.level)
