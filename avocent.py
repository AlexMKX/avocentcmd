from urllib import request
import ssl
import bs4
import re
from lxml import html
from lxml import sax
import lxml.etree as etree
import argparse
import os, sys
import json
import xmltodict
import shutil

from bs4 import BeautifulSoup


def getNodeInfo(url):
    tree = html.fromstring(request.urlopen(request.Request(url), context=ssl._create_unverified_context()).read())
    print("session id %d\tname:%s" % (
        int(re.findall('index=([0-9])', url)[0]), tree.xpath('//input[@name="targetname"]')[0].value))
    pass


def login():
    x = request.Request(
        creds['server'] + "/cgi-bin/kvm.cgi?file=login&action=SAVE&saveParms=login&filename=login&loginUsername=" +
        creds[
            'user'] + "&loginPassword=" + creds['password'])
    resp = request.urlopen(x, context=ssl._create_unverified_context())

    d = resp.read()
    soup = BeautifulSoup(d, 'html.parser')
    kvmurl = [x for x in soup.find_all('meta') if (x.attrs['http-equiv'] == 'Refresh')]
    if kvmurl is None:
        raise str ("Auth problem")

    (x, kvmurl) = kvmurl[0].attrs['content'].split(";url=")
    return kvmurl


def get_nodes(url):
    x = request.Request(creds['server'] + kvmurl)
    resp = request.urlopen(x, context=ssl._create_unverified_context())
    d = resp.read()
    tree = html.fromstring(d)
    nodes_urls = tree.xpath('//*[@id="progressContent"]//a[contains(@href,"overview")]')
    nodes = dict()
    for n in nodes_urls:
        nodes[n.findall('span')[0].text] = int(re.findall('index=([0-9])', n.attrib['href'])[0])
    return nodes


def check_files(webstarturl):
    files = ["avctLinuxLib.jar", "avctMacOSXLib.jar", "avctSolarisLib.jar", "avctVideo.jar", "avctVM.jar",
             "avctWin32Lib.jar", "avmLinuxLib.jar", "avmMacOSXLib.jar", "avmSolarisLib.jar", "avmWin32Lib.jar",
             "jpcscdll.jar", "jpcscso.jar"]
    for f in files:
        if not os.path.exists(f):
            data = request.urlopen(webstarturl + '/' + f).read()
            with open(f, 'wb') as fh:
                fh.write(data)
    if not os.path.exists('j.security'):
        with open("j.security", 'w') as fh:
            fh.write("""
            jdk.certpath.disabledAlgorithms=
            jdk.jar.disabledAlgorithms=
            jdk.tls.disabledAlgorithms=
            jdk.tls.legacyAlgorithms= \
                K_NULL, C_NULL, M_NULL, DHE_DSS_EXPORT, DHE_RSA_EXPORT, DH_anon_EXPORT, DH_DSS_EXPORT, DH_RSA_EXPORT, 
                RSA_EXPORT, DH_anon, ECDH_anon, RC4_128, RC4_40, DES_CBC, DES40_CBC, 3DES_EDE_CBC'"""
                     )
    return


def connect_node(nodes, kvmurl):
    # https://1.1.1.1/cgi-bin/kvm.cgi?&file=jnlp&userID=12312312312&index=1
    global args
    nodeid = None
    if args.id is not None:
        nodeid = args.id
    else:
        if args.name is not None:
            nodeid = nodes[args.name]
    if nodeid is None:
        raise str(print("Wrong node id or name"))

    auth_token = re.findall("userid=([0-9]+)", kvmurl)[0]
    url = creds['server'] + '/cgi-bin/kvm.cgi?file=jnlp&userID=' + auth_token + "&index=" + str(nodeid)
    resp = request.urlopen(request.Request(url), context=ssl._create_unverified_context())
    s = resp.read()

    params = xmltodict.parse(re.compile(".*\<jnlp", flags=re.MULTILINE and re.DOTALL).sub('<jnlp', s.decode()))
    # jre1.8.0_211\bin\java -Djava.security.properties=j.security -cp avctVideo.jar com.avocent.video.Stingray  "path=a:1.1.1.1,p:2,c:0,e:1,s:\"Video Viewer - video\",l:30" "title=\"Avocent DSR2030 - video\"" "devicetype=avsp" "oem=Avocent" "user=Admin" "password=1AVCT-1234123"

    args = ''
    for p in params['jnlp']['application-desc']['argument']:
        args = args + '"' + p.replace('"', '\\"') + '" '
    # args = '"' + (str('" "').join()).replace('""', '\"') + '"'
    check_files(params['jnlp']['@codebase'])
    cmd = ' -Djava.security.properties=j.security -cp avctVideo.jar com.avocent.video.Stingray ' + args
    java = 'java'
    if creds['java'] is not None:
        java = os.path.join(creds['java'], 'java')
    os.execl(java, cmd)
    pass


def main():
    global args, creds, kvmurl
    commands = {'ls', 'save', 'connect'}
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", "-s", type=str,
                        help="server url https://ip.ip.ip.ip/")
    parser.add_argument("--user", "-u", type=str,
                        help="username")
    parser.add_argument("--password", "-p", type=str,
                        help="password")
    parser.add_argument("--name", "-n", type=str,
                        help="session name")
    parser.add_argument("--java", "-j", type=str,
                        help="java")
    parser.add_argument("--id", "-i", type=str,
                        help="session id")

    parser.add_argument("cmd", type=str,
                        help="command" + str(commands))

    args = parser.parse_args()
    if args.cmd not in commands:
        raise str("command not valid, valid commands : %s" % commands)

    haveCreds = True
    if args.user is None or args.password is None or args.server is None:
        if args.cmd == 'save':
            raise str("user/password/server required for config")

        else:
            haveCreds = False

    if args.user is not None or args.password is not None or args.server is not None:
        if args.user is None or args.password is None or args.server is None:
            raise str("If any user/password/server is specified rest must be specified too")


    path = os.path.join(os.getenv('LOCALAPPDATA'), 'avocentcmd')
    if not os.path.exists(path):
        os.makedirs(path)
    os.chdir(path)
    config_path = os.path.join(path, 'avocentcmd.cfg')
    creds = {'user': args.user, 'password': args.password, 'server': args.server, 'java': args.java}
    if args.cmd == 'save':
        j = json.dumps(creds)
        with open(config_path, "w") as f:
            f.write(j)
            print("config saved to %s" % config_path)
        return

    if not haveCreds:
        with  open(config_path, 'r') as f:
            creds = json.loads(f.read())

    kvmurl = login()
    nodes = get_nodes(kvmurl)
    if args.cmd == 'ls':
        for node in nodes:
            print("%d\t%s" % (nodes[node], node))
        return

    if args.cmd == 'connect':
        connect_node(nodes, kvmurl)


cwd = os.getcwd()
try:
    main()
except :
    pass
os.chdir(cwd)
