import os
import json
import time
import socket
import asyncio
import websockets
import logging
import random
import pandas as pd
import pyfpgrowth
import sys
from sqlHelper import sqliteDb
import ipaddress


# Constants
MOD_PORT = 11001
WITH_SUBNET = True
MIN_SUPPORT = 2
SLEEP_DURATION = 10
PROTO_MAP = {'6': 'TCP', '17' : 'UDP'}
# Globals
CONNECTION_TABLE = {}
FIM_OUTPUT = {'0': [], '1':[]}
db_push_q = asyncio.Queue()
lock = asyncio.Lock()
NODE_DICT = {}
CHAR_LIST = [chr(x) for x in range(ord('A'), ord('Z') + 1)] 
GRAPH_DATA_SEQ = ""
GRAPH_DATA_GRAPH = ""

TEMPORAL_GRAPH = []

LAST_KEY_COUNT = 0.0
TOTAL_KEYS = 0.0

logging.basicConfig(level=logging.INFO, filename='log_manager.log', filemode='a', format='%(name)s - %(asctime)s - %(levelname)s  - %(message)s')

def get_masked_ip(i_ip, i_subnet_mask=16):
  try:
    return str(ipaddress.IPv4Network(i_ip+"/"+str(i_subnet_mask), strict=False).network_address)
  except:
    return i_ip


def to_db(i_patterns, i_dir):
    global NODE_DICT, GRAPH_DATA_GRAPH, GRAPH_DATA_SEQ

    for pattern in i_patterns:
        del pattern['Sport']
        if i_dir == '1':
            
            #node_s = "{}-{}".format(pattern['External'], pattern['Sport'])
            #node_d = "{}-{}".format(pattern['IoT'], pattern['Dport'])
            node_s = pattern['External']
            node_d = pattern['IoT']

            if pattern['Traffic'].find('Low') >=0:
                pattern['Meaning'] = 'Scan-In'
            elif pattern['Traffic'].find('Medium') >=0:
                pattern['Meaning'] = 'Login-Attempt'
            else :
                pattern['Meaning'] = 'In N/A'

        else:

            node_d = pattern['External']
            node_s = pattern['IoT']

            #node_d = "{}-{}".format(pattern['External'], pattern['Dport'])
            #node_s = "{}-{}".format(pattern['IoT'], pattern['Sport'])

            if pattern['Traffic'].find('High') >=0 and pattern['External'].find('*')<0:
                pattern['Meaning'] = 'Malware-Download'
            elif pattern['IoT'] == pattern['External']:
                pattern['Meaning'] = 'Scan-Out'
            elif pattern['Traffic'].find('Medium') >=0 and pattern['External'].find('*')<0:
                pattern['Meaning'] = 'C&C Comm.'
            # This is cheating as of now In classification logic, we must include support.
            else:
                pattern['Meaning'] = 'Out N/A'

        sql.update_fim_output(pattern)

        if not node_s in NODE_DICT.keys():
            try:
                NODE_DICT[node_s] = CHAR_LIST.pop(0)
            except:
                logging.error('CHAR LIST has no characters left.')
            
        node_1 = "{}[{}]".format(NODE_DICT[node_s], node_s)    
            
        if not node_d in NODE_DICT.keys():
            try:
                NODE_DICT[node_d] = CHAR_LIST.pop(0)
            except:
                logging.error('CHAR LIST has no characters.')
            
        node_2 = "{}[{}]".format(NODE_DICT[node_d], node_d)

        temp_node_edge_graph = '{}-->|{}|{};'.format(node_1, pattern['Meaning'], node_2) 
        temp_node_edge_seq = '{}->>{}: {};'.format(node_s, node_d, pattern['Meaning'])  

        if GRAPH_DATA_SEQ.find(temp_node_edge_seq) <0:
            GRAPH_DATA_SEQ += temp_node_edge_seq

        #if GRAPH_DATA_GRAPH.find(temp_node_edge_graph) <0:
        ##    GRAPH_DATA_GRAPH += temp_node_edge_graph

        #logging.info(pattern)
    #logging.info(GRAPH_DATA_SEQ)



def get_all_entries():
    ret_list = []
    y = sql.lookup_timed_entries(None)
    if not y is None:
        if len(y) >0 :
            for entry in y:
                try:
                    i = entry[6]
                    if i is None:                       
                        i = 0
                    j = entry[7]
                    if j is None:
                        j = 0

                    io=i+j

                    if io <=100:
                        io='Low'
                    elif io > 100 and io <=900:
                        io='Medium'
                    else:
                        io='High'
                    #ret_list.append(['IoT_'+entry[0], 'External_'+entry[1], 'Sport_'+PROTO_MAP[entry[2]]+'.'+entry[5],'Dport_'+PROTO_MAP[entry[2]]+\
                    #    '.'+entry[3], entry[4], 'Traffic_'+str(io)])

                    ret_list.append([entry[0], entry[1], PROTO_MAP[entry[2]]+'.'+entry[5],PROTO_MAP[entry[2]]+'.'+entry[3], entry[4], str(io)])
                except:
                    logging.error('Exception in get_all_entries.')
                    logging.error(sys.exc_info())


    return pd.DataFrame(ret_list, columns=['IoT', 'External', 'Sport', 'Dport', 'dir', 'Traffic'])
    #return pd.DataFrame(ret_list, columns=['dir', 'intIP', 'extIP', 'sport', 'dport', 'cntBin', 'sizeBin'])
    #df_w.to_csv('entries_'+str(time.time())+'.csv', header=['dir', 'intIP', 'extIP', 'sport', 'dport', 'cntBin', 'sizeBin'],index=False)    
    

# Added for FIM analysis.
def get_subset(i_elem, elem_len_3):
    for some_elem in elem_len_3:
            if set(i_elem).issubset(some_elem):
                return some_elem
    return None


def get_final_patterns(i_patterns):
    key_list = i_patterns.keys()

    final_patterns = i_patterns[max(key_list)]
    for idx in range(max(key_list)-1,1,-1):
        for elem in i_patterns[idx]:
            try:
                l_ret = get_subset(elem, final_patterns)
                if l_ret is None:
                    final_patterns.append(elem)
            except:
                break
    return final_patterns


def get_patterns_by_length(i_pattern):
    ret_patterns = {}
    for i in i_pattern.keys():
        try:
            ret_patterns[len(i)].append(i)
        except:
            ret_patterns[len(i)] = [i]
    return ret_patterns


def run_FIM(i_keys : list):
    y = []
    patterns = pyfpgrowth.find_frequent_patterns(i_keys, MIN_SUPPORT)

    logging.debug(patterns)

    if len(patterns) > 0:
        y2 = get_patterns_by_length(patterns)
        y1 = get_final_patterns(y2)
        for i in y1:
            ret = ''
            for j in i:
                ret += j + ','
            y.append(ret[:-1])
    return y


def get_value(i_s, i_start, i_end = ','):
    t_l = i_s.find(i_start)+len(i_start)
    return i_s[t_l: i_s[t_l:].find(i_end) + t_l ]


async def periodic_task():
    global WITH_SUBNET, GRAPH_DATA_GRAPH, GRAPH_DATA_SEQ, TEMPORAL_GRAPH
    while True:
        await asyncio.sleep(SLEEP_DURATION)
        y = {}
        async with lock:
            fim_input_df = get_all_entries()   

        if WITH_SUBNET == True:
            fim_input_df['IoT'] = list(map(get_masked_ip, fim_input_df['IoT']))
            fim_input_df['External'] = list(map(get_masked_ip, fim_input_df['External']))   

        for col in ['IoT', 'External', 'Sport', 'Dport', 'Traffic']:
            fim_input_df[col] = fim_input_df[col].apply(lambda x: col+'_'+str(x))  

        #GRAPH_DATA_GRAPH = ""
        GRAPH_DATA_SEQ = ""
        
        for k in ['0', '1']:
            v = fim_input_df[fim_input_df['dir']==k][['IoT', 'External', 'Sport', 'Dport', 'Traffic']].values.tolist()
            if len(v) > 0:
                y[k]=run_FIM(v)
                if len(y[k]) > 0:
                    to_db(fill_the_patterns(y[k], ['IoT', 'External',  'Sport', 'Dport', 'Traffic']), k)
        if len(GRAPH_DATA_SEQ)>0:
            TEMPORAL_GRAPH.append(GRAPH_DATA_SEQ)


def fill_the_patterns(i_itemset, i_cols):
    ret_patterns= []
    template_pattern = {}
    for pattern in i_itemset: #self._final_itemset[i_flow_dir]:
        
        template_pattern = {}
        for i in i_cols:
            template_pattern[i]='*'

        for value in pattern.split(','):
            val = value.split('_')
            if val[0] in i_cols:
                template_pattern[val[0]] = val[1]

        ret_patterns.append(template_pattern)

    return ret_patterns    

## END FIM analysis. ##

async def sql_task():
    while True:
        (i,j) = await db_push_q.get()
        async with lock:
            # should we update or create new entry??
            # At the gateway aggregation is happening. Hence, lets add the entry, do not update an old entry.
            sql.insert_db(i,j)


# Process connection anomaly event.
def conn_anomaly(i_payload: dict):
    for i,j in i_payload['key_val'].items():
        asyncio.ensure_future(db_push_q.put((i,j)))


# Send the event to a gateway.
async def send_gateway_event(gateway, event, data):
    global CONNECTION_TABLE
    msg = {}
    msg['timestamp'] = time.time()
    msg['event'] = event
    msg['sender'] = 'master'
    msg['receiver'] = gateway
    msg['data'] = data

    msg = json.dumps(msg)
    try :
        await CONNECTION_TABLE[gateway].send(msg)
    except:
        logging.error("[#] Send failed.")


async def update_gw_count(i_gw, i_count):
    sql.insert_gw_count(i_gw, i_count)


# Process msg. 
async def process_msg(msg, module):
    global TOTAL_KEYS, LAST_KEY_COUNT, GRAPH_DATA_SEQ, TEMPORAL_GRAPH

    msg = json.loads(msg)

    if not ('event' in msg.keys() and 'data' in msg.keys()):
        logging.error("Event not in the message.")
        return
    
    event = msg['event']
    payload = msg['data']

    if event == "EVT_CONN_ANOMALY":
        asyncio.ensure_future(update_gw_count(msg['sender'], len(payload['key_val'])))
        TOTAL_KEYS += len(payload['key_val'])
        logging.info("Gateway - {} - Data size - {} - Total keys - {}/{}".format(msg['sender'], len(payload['key_val']), TOTAL_KEYS, TOTAL_KEYS - LAST_KEY_COUNT))
        LAST_KEY_COUNT = TOTAL_KEYS
        conn_anomaly(payload)

    elif event == "EVT_BEHV_ANOMALY":
        pass
    elif event == "EVT_QUERY_RESPONSE":
        pass
    elif event == "EVT_GET_GRAPH":
        resp = '<!DOCTYPE html><html><head><meta charset="UTF-8"><script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/8.0.0/mermaid.min.js">\
        </script></head><body><pre><code class="language-mermaid">sequenceDiagram;'+GRAPH_DATA_SEQ+'</code></pre></body><script>\
        var config = {startOnLoad:true,theme: "dark", flowchart:{useMaxWidth:true, htmlLabels:true}};\
        mermaid.initialize(config);window.mermaid.init(undefined, document.querySelectorAll(".language-mermaid"));</script></html>'

        asyncio.ensure_future(send_gateway_event('graph', 'EVT_GET_GRAPH', resp))
    elif event == "EVT_GET_TIMED_GRAPH":
        resp = {}
        try:
            resp['html_data'] = '<!DOCTYPE html><html><head><meta charset="UTF-8"><script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/8.0.0/mermaid.min.js">\
            </script></head><body><pre><code class="language-mermaid">sequenceDiagram;'+TEMPORAL_GRAPH[int(payload["time"])]+'</code></pre></body><script>\
            var config = {startOnLoad:true,theme: "dark", flowchart:{useMaxWidth:true, htmlLabels:true}};\
            mermaid.initialize(config);window.mermaid.init(undefined, document.querySelectorAll(".language-mermaid"));</script></html>'
        except:
            resp['html_data'] = ''
        resp['count'] = len(TEMPORAL_GRAPH)
        asyncio.ensure_future(send_gateway_event('timed_graph', 'EVT_GET_TIMED_GRAPH', resp))
    elif event == "EVT_GW_DEVICES":
        logging.info("Gateway: {}, devices: {}".format(msg['sender'], payload))
    elif event == "EVT_GET_TIMED_GRAPH_COUNT":
        resp = {}
        resp['count'] = len(TEMPORAL_GRAPH)
        asyncio.ensure_future(send_gateway_event('timed_graph', 'EVT_GET_TIMED_GRAPH_COUNT', resp))
    else:
        logging.error('Unknown event received.')


# Receiver events.
async def recv_module_event(websocket, path):
    global CONNECTION_TABLE
    module = os.path.basename(path)
    logging.info('Module {}, Address {}'.format(module, websocket.remote_address))
    CONNECTION_TABLE[module] = websocket
    try:
        while(True) :
            msg = await websocket.recv()
            logging.info("Received msg: {}".format(msg))
            await process_msg(msg, websocket)

    except websockets.exceptions.ConnectionClosed:
        del CONNECTION_TABLE[module]
        logging.debug('Connection closed by module: {}'.format(module))    
        

sql = sqliteDb("alerts")
EVENT_LOOP = asyncio.get_event_loop()
task = websockets.serve(recv_module_event, '0.0.0.0', MOD_PORT)

EVENT_LOOP.run_until_complete(task)
asyncio.ensure_future(sql_task())
asyncio.ensure_future(periodic_task())

start_time = time.time()

try:
    logging.info("Starting event loop.")
    EVENT_LOOP.run_forever()
except KeyboardInterrupt:
    pass
finally:
    get_all_entries()
    logging.info('Running time {} seconds. Rx keys: {}. Unique Keys: {}'.format(time.time() - start_time, TOTAL_KEYS, sql.get_count()))
    sql.db_close()
    logging.info('!!!! Module Closed !!!!.')


"""
def output_meaning(i_input : dict):
    
    global FIM_OUTPUT
    
    for dirn, rules in i_input.items():
        if dirn == '0':
            for rule in rules:
                    
                    temp_scan = ""
                    if rule.find('c_0')>=0 and rule.find('s_0') >= 0:
                        temp_scan = 'Scan-out'
                    elif rule.find('c_1') >= 0 and  rule.find('s_3') >= 0:
                        temp_scan = 'Loader'
                    elif rule.find('c_1') >= 0 and  rule.find('s_1') >= 0:
                        temp_scan = 'C&C'
                    elif rule.find('c_1') >= 0 and  rule.find('s_2') >= 0:
                        temp_scan = 'HTTP DDoS'
                    else:
                        temp_scan = 'New Pattern'
                    t_msg = ' Out - {}:{}'.format(temp_scan, rule)

                    if not t_msg in FIM_OUTPUT[dirn]:
                        FIM_OUTPUT[dirn].append(t_msg)
                        logging.info(t_msg)


        elif dirn == '1':
            for rule in rules:

                    temp_scan = ""
                    if rule.find('c_0')>=0 and rule.find('s_0') >= 0:
                        temp_scan = 'Scan-in'
                    elif rule.find('c_2') >= 0 and rule.find('s_2') >= 0:
                        temp_scan = 'Login'
                    else:
                        temp_scan = 'New Pattern'

                    t_msg = 'In - {}:{}'.format(temp_scan, rule)

                    if not t_msg in FIM_OUTPUT[dirn]:
                        FIM_OUTPUT[dirn].append(t_msg)
                        logging.info(t_msg)            
        else:
            pass
"""
