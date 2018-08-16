# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0004'  # 平台漏洞编号，留空
    name = 'WordPress DomXSS'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-05-08'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        该漏洞存在于 WordPress 流行的 Genericons example.html 页面中，
        默认主题 Twenty Fifteen 及知名插件 Jetpack 都内置了该页面，
        由于 example.html 使用了老版本存在 DOM XSS 缺陷的 jQuery，且使用不当，
        导致出现 DOM XSS，这种攻击将无视浏览器的 XSS Filter 防御。
    '''  # 漏洞描述
    ref = 'http://www.freebuf.com/news/66695.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = '使用了Genericons包的WordPress插件或主题'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3645cc3a-1eeb-42ce-b1df-2c0ff774f3fe'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            verify_url = '%s/wp-content/themes/twentyfifteen/genericons/example.html' % self.target
            req = requests.get(verify_url)
            if req.status_code == 200:
                if 'jquery/1.7.2/jquery.min.js"></script>' in req.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
