import sys
import os.path
from xml.dom import minidom
import shutil

sens_dir = "/opt/IntruSense-v30/"
webserver_dir = ""
warn_code = list()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def cleanup(warn_num,file_name):
    if warn_num == 10: os.remove(webserver_dir+"/"+file_name)
    if warn_num == 3: shutil.move(file_name+".bak",file_name)
    if warn_num == 9: os.remove(file_name)

def check_01(scan_type,file_name,warn_num,secopx_log):
    msg = "["+scan_type+"]: "
    stat = 0
    scan_result = ""
    node = secopx_log.getElementsByTagName(scan_type)
    
    for c in node[0].childNodes : scan_result += c.data
    if file_name[:file_name.index(".")] in scan_result:   
        msg += "\n\t"+file_name+" has been captured in scan. "
        stat = 1
    else:
        msg += "\n\t"+bcolors.FAIL+"FAILED to capture "+file_name+bcolors.ENDC
        print(msg); return stat
    
    if warn_num == 8 or  warn_num == 4 :
        q_file = sens_dir+"quarantine/"+webserver_dir.replace("/","%")+"%"+file_name+".zip"
        if not os.path.isfile(webserver_dir+file_name) and os.path.isfile(q_file):
            msg += "\n\t"+file_name+" has been moved to quarantine! "
            stat = 2
        else:
            msg += "\n\t"+bcolors.FAIL+"FAILED to move "+file_name+" to quarantine!"+bcolors.ENDC
            print(msg); return stat
    
    if len(warn_code) >= warn_num and warn_code[warn_num] == "1":
        msg += "\n\tWarning created. "
        stat = 3
    else:
        msg += "\n\t"+bcolors.FAIL+"Failed to raise warning!"+bcolors.ENDC
        print(msg); return stat 
    
    if stat == 3: msg +="\n\t"+bcolors.OKGREEN+"Test completed successfuly!"+bcolors.ENDC
    cleanup(warn_num,file_name)
    print(msg); return stat

def check_02(scan_type,file_name,warn_num,secopx_log):
    msg = "["+scan_type+"]: "
    stat = 0
    scan_result = ""
    node = secopx_log.getElementsByTagName(scan_type)
    
    for c in node[0].childNodes : scan_result += c.data.lower()
    if scan_type == "chkrootkit": fn = file_name[file_name.rindex("/")+1:file_name.index(".")]
    else: fn = file_name
    if fn in scan_result:
        msg += "\n\t"+file_name+" has been captured in scan. "
        stat = 1
    else:
        msg += "\n\t"+bcolors.FAIL+"FAILED to capture "+file_name+bcolors.ENDC
        print(msg); return stat
    
    if len(warn_code) >= warn_num and warn_code[warn_num] == "1":
        msg += "\n\tWarning created. "
        stat = 3
    else:
        msg += "\n\t"+bcolors.FAIL+"Failed to raise warning!"+bcolors.ENDC
        print(msg); return stat
    
    if stat == 3: msg +="\n\t"+bcolors.OKGREEN+"Test completed successfuly!"+bcolors.ENDC
    cleanup(warn_num,file_name)
    print(msg); return stat

def check_03(scan_type,file_name,warn_num,secopx_log):
    msg = "["+scan_type+"]: "
    stat = 0
    scan_result = ""
    node = secopx_log.getElementsByTagName(scan_type)
    for c in node[0].childNodes : scan_result += c.data.lower()
    if scan_type == "chkrootkit": fn = file_name[file_name.rindex("/")+1:file_name.index(".")]
    else: fn = file_name
    if fn in scan_result:
        msg += "\n\t"+file_name+" has been captured in scan. "
        stat = 1
    else:
        msg += "\n\t"+bcolors.FAIL+"FAILED to capture "+file_name+bcolors.ENDC
        print(msg); return stat

    if stat == 1: msg +="\n\t"+bcolors.OKGREEN+"Test completed successfuly!"+bcolors.ENDC
    print(msg); return stat


if __name__ == "__main__":
    webserver_dir = ""
    conf = open("/opt/IntruSense-v30/secopx.conf","r")
    confread = conf.read()
    lines = confread.splitlines()
    for l in lines:
        if 'WEBSERVER_DIR' in l: webserver_dir = l.replace('WEBSERVER_DIR=','').replace("'","").replace('"',"").strip()

    secopx_log = minidom.parse('/opt/IntruSense-v30/tmp/secopx.xml')
    node = secopx_log.getElementsByTagName('warnings')  
    warnings = node[0].firstChild.data.strip()
    warn_code = list(warnings)
    warn_code.reverse()
    if "--yara" in sys.argv or "--all" in sys.argv : check_01("yara","RAASNet.py",8,secopx_log)
    if "--webshells" in sys.argv or "--all" in sys.argv : check_01("webshelllist","c99.php",8,secopx_log)
    if "--coinscan" in sys.argv or "--all" in sys.argv : check_01("possiblecryptojack","miner.js",4,secopx_log)
    if "--predictor" in sys.argv or "--all" in sys.argv : check_01("predictor","ajaxshell.php",10,secopx_log)
    if "--btmp" in sys.argv or "--all" in sys.argv : check_02("btmp","/var/log/btmp",3,secopx_log)
    if "--chkrootkit" in sys.argv or "--all" in sys.argv : check_02("chkrootkit","/tmp/ramen.tgz",9,secopx_log)
    if "--scalp" in sys.argv or "--all" in sys.argv : check_03("scalp","hellothinkcmf",-1,secopx_log)
    if "--dos" in sys.argv or "--all" in sys.argv : check_03("dos","hellothinkcmf",-1,secopx_log)
