# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Info_Git' # 平台漏洞编号，留空
    name = 'Git 源码泄露' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
    当前大量开发人员使用git进行版本控制，对站点自动部署。如果配置不当，可能会将.git文件夹直接部署到线上环境。这就引起了git泄露漏洞。
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Info_Git(Git源码泄露)'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):s
    author = 'cscan'  # POC编写者
    create_date = '2018-04-26' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.get('{target}/.git/'.format(target=self.target))
            if request.status_code == 200:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))


    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
