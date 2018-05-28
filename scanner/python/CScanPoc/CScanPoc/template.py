# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    ###脚本名称 和 “vuln_id” 保持一致，主要使用对应组件的名称命名，若同一厂商有多个组件，则直接使用厂商名称，
    ###大小写采用驼峰原则（每个单词的首字母大写，包括汉语拼音），若涉及到简称的全部使用大写，比如：CMS、OA等。命名规范适用全局。
    vuln_id = 'CScan_0001' # 平台漏洞编号
    ###国外的组件名称使用英文，国内的组件名称尽量使用中文，中文与英文之间应有适当空格隔开，名称最后不要添加“漏洞”二字。
    ###另外，在明确表示出漏洞名称的前提下，遵循最简原则。
    name = '模版 SQL注入' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    ###未查到公布时间写：Unknown
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    ###描述必须写，且尽可能地详细。描述正文保持缩进，中文末尾应用中文标点，英文末尾应用英文标点，中文与英文之间应有适当空格隔开。
    desc = '''模版漏洞描述
        更多描述...
    ''' # 漏洞描述
    ###未查到来源写：Unknown
    ref = 'http://alpha.hu0g4.com/' # 漏洞来源
    ###未查到编号写：Unknown
    cnvd_id = '0000' # cnvd漏洞编号
    ###未查到编号写：Unknown
    cve_id = '0000'  # cve编号
    ###组件名称涉及到漏洞的归类（重点），使用“厂商+组件名称”方式命名，国内组件应在括号内补充中文名称，比如：74CMS(骑士CMS)，采用英文状态下的括号。
    product = '应用名称'  # 漏洞组件名称
    ###未查到版本信息写：Unknown
    product_version = '应用版本'  # 漏洞应用版本

class Poc(ABPoc):
    ###UUID的随机数
    poc_id = '3c6b7330-5012-4a6c-bd45-d2f2f631abef' # 平台 POC 编号
    ###填写编写者ID
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
        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
