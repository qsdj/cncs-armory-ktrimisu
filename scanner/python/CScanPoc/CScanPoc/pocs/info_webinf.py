# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Info_webinf' # 平台漏洞编号，留空
    name = 'WEB/INF/web.xml 文件泄露' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        WEB-INF是Java的Web应用的安全目录,如果没有配置得到可以被外部直接访问到的话,有造成敏感信息泄露的风险.
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Info_webinf'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '599e2fee-a65d-4d9f-bc24-2e904eac2133'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-26' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.get('{target}/WEB-INF/web.xml'.format(target=self.target))
            if request.status_code == 200:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))


    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
