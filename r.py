# %%snakeviz
# %load_ext snakeviz
# ln -s /home/splunker/splunk_fdse /bin/splunk_fdse

import json
import os
import requests
import time   
import socket
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
TIME_EXEC = int(time.time())

ENV = "SS_TEST" # "SS_TEST" # or SPLUNK or SS_TEST, SS_DEV, SS_PROD



if ENV == "SS_TEST":
    proto = "http"
    host = "jabdlpc0042"
    port = "8088"
    token = "366051e4-42c7-487e-a671-9fa42e67d600"
    index = "refinitiv"
    BIN_FILE = "/root/test/splunk_fdse"
elif ENV == "SS_DEV":
    proto = "https"
    host = "gov-data.statestr.com"
    port = "443"
    token = "1209e507-6818-4cae-a6d9-b7d12a448371"
    index = "application_logs"
elif ENV == "SS_PROD":
    proto = "https"
    host = "gov-data.statestr.com"
    port = "443"
    token = "1209e507-6818-4cae-a6d9-b7d12a448371"
    index = "application_logs"
else:
    # FDSE.splunk.link
    proto = "https"
    host = "fdse.splunk.link"
    token = "d43715d0-282e-4b6b-92d6-d231ddd04616"
    port = "8088"
    index = "main"
    BIN_FILE = "splunk_fdse"


TIMEOUT = 8
CURRENT_HOST_NAME = socket.gethostname()

# ipc commands
cmd_ipc_human = """ipcs -m --human | grep -v "shm" | grep -v "\-\-\-" | awk 'NF > 0'  | awk '{print $1,$2,$3,$4,$5,$6}'  """
cmd_ipc_shm_creator_last_opened = """ipcs -m -p | grep -v "shm" | grep -v "\-\-\-" | awk 'NF > 0' | awk '{print $1,$2,$3,$4}' """

# pids comes from ipc
tied_processes_cmd = "ps -p {} -o cmd --no-headers"
tied_processes_cpu = "ps -p {} -o %cpu --no-headers"
tied_processes_mem = "ps -p {} -o %mem --no-headers"



# dacs: 1427
# ats: 60
# adh: 80
# ads: 82

# EXHAUSTIVE PROD
cmds = {
"dac": 
    [
        "rrcp_trans", # dacs_TransInfo
        "dacs_trans.dacs.snkd.SnkdFrmSvr", # dacs_SnkdInfo
        "dacs_trans.dacs.snkd", # dacs_SnkdInfo
        "dacs_trans.dacs_svr", # dacs_configs
        "dacs_trans.dacs_svr.Systems", # dacs SrvInfo
        "dacs_trans.dacs_svr.Sizes" # dacs SrvSizes
    ],
"ats":
[
    "ats.server statistics.statistic current hour", # ats stats
    "ats.server statistic.dictionary statistic", # BU
    "ats.memorystats", # Memory
    "ats.license information",  # LICENSE
    "ats.license information.number_of_open_items" # License#ofOpenItems => featurevalue 
],
"adh": [
    "adh.rrmpconsumer", # services
    "adh", # adh_info
    "adh.trlsManager", # adh_info
    "adh.serviceGenerator.srcPrdServicePool", #ComInfo1 (ComInfo is in ADHMON)
    
    
],

"ads":
[
    "ads.dacs", # ads info
    "ads", # ads info
    "ads.trlsManager", # ads info
    "ads.servicedb", # ads Server
    "ads.itermdatabase", # ads Services
    "ads.userDatabase", # ads user + ads mounts
    "ads.userdatabase.userrequests" # TITLE
    
]
}






def l(msg):
    print('{}'.format(msg))


def run_cmd(cmd):
    return os.popen(cmd).read().strip()




def cuts(msg, start, end):
    # text = 'gfgfdAAA1234ZZZuijjk'
    #cuts(text,"AA","ZZ")

    try:
        return msg.partition(start)[2].partition(end)[0]
    except Exception as e:
        ss(e, "error:cuts")
    
    
def ss(msg, sourcetype):
    url = "{}://{}:{}/services/collector/event".format(proto, host, port)

    
    try:
        if isinstance(msg, str):
            event = json.loads(msg.strip())
            sourcetype = event['instanceId']
            # del event['instanceId']
        
    except Exception as e:
        event = str(msg)
        # print("e: {}".format(e)) #### 
        sourcetype = "log"
        ## pass
    
    try:
        payload = json.dumps({
          "time": TIME_EXEC,
          "sourcetype": "refinitiv:{}".format(sourcetype),
          "source": "refinitiv",
          "host": CURRENT_HOST_NAME,
          "index": index,
          "event": event
        }, indent=2)
        
        headers = {
          'Authorization': 'Splunk {}'.format(token),
          'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        if response.status_code not in range (200,301):
            print(response.text)
    except Exception as e:
        pass
        # print(e)
        # ss(e, "error:hec")
    
    #print(msg)
    return






# Detect IPC
ipc_human = run_cmd(cmd_ipc_human)
ipc_clo = run_cmd(cmd_ipc_shm_creator_last_opened)


shm = {}
for ipc in ipc_human.split("\n"):
    field = ipc.split(" ")
    # primary key (shmid) =>field[1]
    if len(field) > 2:
        shm[field[1]] = { # shmid
            "key_hex": field[0], #
            "shmid": field[1],
            "owner": field[2],
            "perms": field[3],
            "size": field[4],
            "nattch": field[5],
        }

## Create DICT
for ipc in ipc_clo.split("\n"):
    field = ipc.split(" ")
    # primary key (shmid) =>field[0]
    if len(field) > 2:
        pid = field[2]
        lpid = field[3]
        shmid = field[0]
        
        shm[shmid]["key_decimal"] = int(shm[shmid]["key_hex"], 16)# int(hex_s, 16)
        shm[shmid]["pid_creator"] = pid
        shm[shmid]["pid_lastacessed"] = lpid
        shm[shmid]["process"] = run_cmd(tied_processes_cmd.format(pid))
        shm[shmid]["cpu_perc"] = run_cmd(tied_processes_cpu.format(pid))
        shm[shmid]["memory_perc"] = run_cmd(tied_processes_mem.format(pid))        


## Call to C binary
def async_exec(key, component, cmd_arg):
    CUT_START = "Start output data"
    CLEAN_DATA = '(Apply filter)'

    try:
        # run c code : splunk_fdse
        final_cmd = 'timeout {} {} {} \"{}\"'.format(TIMEOUT, BIN_FILE, key, cmd_arg)
        stdout = run_cmd(final_cmd)
        # print ("== final_cmd: {}\n\n".format(final_cmd))
        # print ("== event {} \n== event end".format(stdout))
        # break ##################
        # print(stdout)
        ####
        try:
            # process event
            events = stdout.split(CUT_START)[1].replace(CLEAN_DATA,'').split("},")
            # print (events)
            for event in events:
                se = event + "}"
                se = se.replace('"\n', '",\n').replace(',\n}','}')  ###### DICT OUT IS NOT VALID JSON

                ## SEND TO SPLUNK
                # ss(se, "{}:{}".format(component, cmd_arg))
                # print(se)
                
                if "!!!!!!!!!!!!" in se:
                    se = se.split('filter list')[-1]
                    # print(se)
                ss(se, component)

                # break ###########################
        except Exception as e:
                ss(e, "error:process_event")
                pass
    except Exception as e:
            ss(e, "error:cmd")

            
## MAIN ()

## PROCESS IPC SHM Entries

print("=== Splunk FDSE : Refinitiv ===")
for s in shm:
    # l(s)
    comp = shm[s]
    
    cb = json.dumps(comp,indent=2)
    
    try:
        process_name = comp['process'][2:5].lower().strip()
        key_decimal = comp["key_decimal"] 
        if process_name in ['ads','adh', 'ats', 'dac'] and key_decimal < 5000:
            # SEND TO HEC
            
            # l(cb) # refinitiv:ipc
            ss(cb, "ipc")
            # l("{}|{}".format(process_name, comp['key_decimal'] ))   # ads|82
            
            
            QUERY_ARG = ",{}.1.".format(CURRENT_HOST_NAME).join(cmds[process_name])
            QUERY_ARG = "{}.1.{}".format(CURRENT_HOST_NAME,QUERY_ARG )
            
            
            async_exec(key_decimal, process_name, QUERY_ARG  )
            ## EXEC splk_fdse_2 | stdout
            # COMBINE ARRAY?
            # QUERY_ARG = ",".join(cmds[process_name])
            # print(QUERY_ARG)

                

        else:
            ss("Refinitiv Debug: {} - {}".format(process_name, comp), "log:extra_ipc")
    
    except Exception as e:
        ss("Refinitiv Exception: {}".format(e), "error:cmd")
        pass
        


                

