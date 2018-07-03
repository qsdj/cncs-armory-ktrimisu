# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Info_Manage' # 平台漏洞编号，留空
    name = '管理后台地址暴露' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        直接将Web后台的管理地址暴露在外面可能会被攻击者进行攻击利用,带来不安全因素.
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Info_Manage'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a159219e-61fa-467e-b9f0-b8dc8ee350c2'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-28' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #讲常见的后台地址组成list,循环去请求是否存在默认后台地址
            dict_list = ['admin','manage','manager','administrator','houtai','admin_login.asp','admin_login.php','admin.php','admin.asp','login_admin.asp','login_admin.php','manage.asp','manager.asp','manage.php','manager.php','guanli','guanli.asp','guanli.php','adminlogin','adminadmin','ad','ad.asp','ad.php','ad_login','ad_login.asp','ad_login.php','admin_admin','admin_admin.asp','admin_admin.php','admin_login']
            keywords = ['user', 'passwd', 'username', 'password', 'adminstartor', u'管理', u'后台', u'密码', u'登录']
            for payload in dict_list:
                url = self.target + "/" +payload
                request = requests.get(url)

                if request.status_code == 200:
                    for keyword in keywords:
                        if keyword in request.text:
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞;url={url}'.format(target=self.target,name=self.vuln.name, url=url))
                            continue

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


    def exploit(self):
        # 这里直接将后台地址输出来
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
            dict_list = ['admin','manage','manager','administrator','houtai','admin_login.asp','admin_login.php','admin.php','admin.asp','login_admin.asp','login_admin.php','manage.asp','manager.asp','manage.php','manager.php','guanli','guanli.asp','guanli.php','adminlogin','adminadmin','ad','ad.asp','ad.php','ad_login','ad_login.asp','ad_login.php','admin_admin','admin_admin.asp','admin_admin.php','admin_login']
            keywords = ['user', 'passwd', 'username', 'password', 'adminstartor', u'管理', u'后台', u'密码', u'登录']
            for payload in dict_list:
                url = self.target + "/" +payload
                request = requests.get(url)
                if request.status_code == 200:
                    for keyword in keywords:
                        if keyword in request.text:
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞,网站当前后台底地址为:\n{url}'.format(target=self.target,name=self.vuln.name,url=request.url))
                            continue

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

if __name__ == '__main__':
    Poc().run()
