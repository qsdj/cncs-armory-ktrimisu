# -*- coding: utf-8 -*-

import os
import re
import shlex
import logging
import argparse
from subprocess import PIPE, Popen

FORMAT = '%(levelname)s: %(asctime)-15s: %(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)


class HydraScanner:
    def __init__(self, args, service, scan_level, username_file=None, password_file=None):
        self.args = args
        self.service = service
        self.username_file = (
            username_file if username_file else "./hydra_dicts/CommonUsername.txt")
        self.password_file = (
            password_file if password_file else "./hydra_dicts/CommonPasswds.txt")
        self.stdout = ''
        self.stderr = ''
        self.result = []

    def scanner(self):
        command = self._format_args()
        logging.info("{}: hydra scan start".format(self.args))
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        logging.info("{}: hydra scan end".format(self.args))
        try:
            (self.stdout, self.stderr) = process.communicate()
        except Exception as e:
            logging.error("res:{} Exception:{}".format(process.pid, e))
        return self._format_res()

    def _format_args(self):
        # The redis, cisco, oracle-listener, s7-300, snmp and vnc modules
        # are only using the -p or -P option, not login (-l, -L) or colon file (-C)
        if self.service in ['redis', 'cisco', 'oracle-listener', 's7-300', 'snmp', 'vnc']:
            command = 'hydra -w 15 -P {passdict} {args} {service}'.format(
                passdict=self.password_file, args=self.args, service=self.service)
        else:
            # use -L/-P options
            command = 'hydra -w 15 -L {userdict} -P {passdict} {args} {service}'.format(
                userdict=self.username_file, passdict=self.password_file, args=self.args, service=self.service)
        return shlex.split(command)

    def _format_res(self):
        result_list = []
        result = {}
        pattern_res = r'(\[\d+\]\[%s\]\shost:\s\d+\.\d+\.\d+\.\d+.*?)\n' % self.service
        pattern_host = r'host:\s(\d+\.\d+\.\d+\.\d+)\s'
        pattern_username = r'login:\s(.+?)\s+password:'
        pattern_password = r'password:\s(.+?)$'
        logging.info(self.stdout.decode('utf-8'))
        re_result = re.findall(pattern_res, self.stdout.decode('utf-8'))
        for res in re_result:
            try:
                if re.findall(pattern_host, res):
                    host = re.findall(pattern_host, res)[0]
                else:
                    host = 'None'
                if re.findall(pattern_username, res):
                    username = re.findall(pattern_username, res)[0]
                else:
                    username = "None"
                if re.findall(pattern_password, res):
                    password = re.findall(pattern_password, res)[0]
                else:
                    password = "None"
                result['target'] = host
                result['service'] = self.service
                result['username'] = username
                result['password'] = password
                result_list.append(result)
                result = {}
            except Exception as e:
                logging.error("_format_res:{} Exception:{}".format(res, e))
        return result_list


def create_cmd_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '--target', required=True, type=str, dest='target',
        help='目标主机 URL/IP/域名')
    parser.add_argument(
        '--service', required=True, type=str, dest='service',
        help='目标主机服务')
    parser.add_argument(
        '--username_file', required=False, type=int, dest='username_file',
        help='用户名列表字典')
    parser.add_argument(
        '--password_file', required=False, type=int, dest='password_file',
        help='密码列表字典')
    return parser


def analysis_result(result_list):
    result = list()
    result_str = ''
    for result_dict in result_list:
        for key, item in result_dict.items():
            result_str += "{key}:{item};".format(key=key, item=item)
        result.append(result_str)
        result_str = ''
    return result


def main():
    parser = create_cmd_parser()
    args = parser.parse_args()
    if args.target and args.service:
        result = HydraScanner(args.target, args.service,
                              args.username_file, args.password_file).scanner()
        if result:
            logging.info(u"Password explosion successful: {}".format('\n'.join(analysis_result(result))))
        else:
            logging.info(u"Password explosion failed")


if __name__ == "__main__":
    main()
