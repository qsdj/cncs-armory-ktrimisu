# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = '' # 平台漏洞编号，留空
    name = '模版漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''模版漏洞描述
    更多描述...
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    product = '应用名称'  # 漏洞应用名称
    product_version = '应用版本'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '' # 平台 POC 编号，留空
    author = 'cscan'  # POC编写者
    create_date = '2018-3-24' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
            target=self.target, vuln=self.vuln))

        self.output.info('执行操作1....')
        self.output.warn(self.vuln, '疑似信息xxxx')
        # ...
        self.output.info('执行操作2....')
        self.output.report(self.vuln, '发现漏洞信息xxxx')

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
