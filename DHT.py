import socket
import Bencode
import random
import string
import struct
import hashlib
import time
from math import inf

import logging
import struct
import pickle


ascii_full = string.ascii_letters+'1234567890'

def count_digits(number:int):
    count = 0
    while number>0:
        number = number//10
        count += 1
    return count

def get_id(hash:bytes):
    #converted = struct.unpack('>QQI',hash)
    #digits = count_digits(converted[2])
    #id = converted[2]
   
    #id += converted[1]*(10**(digits))
    #digits += count_digits(converted[1])

    #id += converted[0]*(10**(digits))
    id = 0
    for byte in hash:
        id += byte
    return id

def distance_estimation(first:bytes,second:bytes)->int:
    if len(first) != len(second):
        return False
    to_return = 0
    for i in range(len(first)):
        to_return += first[i] ^ second[i]
    return to_return

def decode_ip(encoded_ip:int):
    ip_decoded = ''

    for i in range(3,-1,-1):
        num = encoded_ip//(256**i)
        encoded_ip = encoded_ip - num*(256**i)
        ip_decoded += str(num)+'.'
    return ip_decoded[0:len(ip_decoded)-1]

def encode_ip(ip:str):
    nums = ip.split('.')
    to_return = 0
    for i in range(4):
        to_return += int(nums[i]) * (256**(3-i))
    return to_return

def reverse(data):
    if type(data) == bytes:
        to_return = b''
        for i in range(len(data)-1,-1,-1):
            to_return += struct.pack('B',data[i])
    else:
        to_return = ''    
        for i in range(len(data)-1,-1,-1):
            to_return += data[i]
    return to_return

def parse_nodes_info(data)->list:
    to_return = []
    if len(data) % 26 == 0:
        for i in range(len(data)//26):
            buf = []           
            buf.append(data[i:i+20])
            buf.append((decode_ip(struct.unpack('>I',data[i+20:i+24])[0]),struct.unpack('>H',data[i+24:i+26])[0]))
            to_return.append(buf)            
        return to_return
            
    else:
        raise Exception('data % 26 != 0!')

class Node:
    def __init__(self,address:tuple,id=''):
        self.id = id
        self.hash_info = ''
        self.token = ''
        self.issued_token = ''
        self.address = address
        self.last_changed = time.time()
        self.fails = 0


    def get_compact_info(self):        
        return self.id + struct.pack('>I',encode_ip(self.address[0])) + struct.pack('>H',self.address[1])

    def set_id(self,id):
        self.id = id

    def issue_token(self):
        self.issued_token = bytes(''.join(random.choices(ascii_full,k=8)),'ascii')
        return self.issued_token

    def update_time(self):
        self.last_changed = time.time()


    def alive(self,failtime=900):
        if time.time() - self.last_changed>=failtime:
            self.fails += 1
            return False
        return True

    def get_fail(self):
        return self.fails

    def fail(self):
        self.fails += 1


class HashTable:
    def __init__(self,start_max_buckets=1,max_per_bucket=8):
        self.max_buckets = start_max_buckets
        self.max_per_bucket = max_per_bucket
        self.buckets = []
        for i in range(self.max_buckets):
            self.buckets.append([])

    def set(self,node:Node,bucket_number=None,failtime=900,check = True):
        if check:
            find_result = self.find_node(node.id)
            if isinstance(find_result,Node):
                return
        id = get_id(node.id)
        if bucket_number == None:
            bucket_number = id%self.max_buckets
        popped_node = node
        while popped_node!=None and bucket_number<len(self.buckets):
            if len(self.buckets[bucket_number])<self.max_per_bucket:
                self.buckets[bucket_number].append(node)
                popped_node = None
                break
            for nd in enumerate(self.buckets[bucket_number]):
                if id<get_id(nd[1].id) or not nd[1].alive(failtime):
                    self.buckets[bucket_number].insert(nd[0],popped_node)
                    if len(self.buckets[bucket_number])>self.max_per_bucket:
                        popped_node = self.buckets[bucket_number].pop()
                    else:
                        popped_node = None
                
            bucket_number += 1
        if bucket_number == len(self.buckets) and popped_node!=None:
            self.append_buckets()
            self.set(popped_node,failtime=failtime)

    def remove(self,node:Node):
        bucket_index_original = self.get_bucket_index_not_empty(node.id)
        for bucket_index in range(bucket_index_original,len(self.buckets)):
            for place,node_iter in enumerate(self.buckets[bucket_index]):
                if node_iter.id == node.id:
                    del self.buckets[bucket_index][place]
                    return 

                    

    def append_buckets(self,failtime=900):
        old_buckets = self.buckets
        self.buckets = []
        self.max_buckets += 1
        for i in range(self.max_buckets):
            self.buckets.append([])
        for bucket in old_buckets:
            for node in bucket:
                self.set(node,failtime=failtime)

    def get_bucket_index(self,hash:bytes):
        id = get_id(hash)
        return id%self.max_buckets

    def find_node(self,hash:bytes):
        bucket_index_original = self.get_bucket_index(hash)
        #bucket_index = bucket_index_original
        for bucket_index in range(bucket_index_original,len(self.buckets)):
            for node in self.buckets[bucket_index]:
                if node.id == hash:
                    return node
        return self.buckets[bucket_index_original]

    def get_bucket_index_not_empty(self,hash:bytes):
        id = get_id(hash)%self.max_buckets
        new_id = id
        while len(self.buckets[new_id]) == 0 and new_id<self.max_buckets:
            new_id += 1
        if len(self.buckets[new_id]) == 0 and new_id<self.max_buckets:
            return new_id
        new_id = id
        while len(self.buckets[new_id]) == 0 and new_id>0:
            new_id -= 1 
        return new_id


    def get_bucket(self,index:int):
        return self.buckets[index]
    


ENTRYPOINTS = []


ENTRYPOINT = 'dht.libtorrent.org'
ENTRYPOINTS.append((socket.gethostbyname(ENTRYPOINT),25401))

ENTRYPOINT = 'router.bittorrent.com'
ENTRYPOINTS.append((socket.gethostbyname(ENTRYPOINT),6881))

ENTRYPOINT = 'router.utorrent.com'
ENTRYPOINTS.append((socket.gethostbyname(ENTRYPOINT),6881))

ENTRYPOINT = 'dht.transmissionbt.com'
ENTRYPOINTS.append((socket.gethostbyname(ENTRYPOINT),6881))










class DHT:
    def __init__(self,id=None,start_max_buckets=1,max_per_bucket=8,failtime=900,max_fails=9,dht_port=6969,download_port=None):
        self.failtime = failtime
        self.max_fail = max_fails

        self.hashtable = HashTable(start_max_buckets,max_per_bucket)

        self.dht_port = dht_port
        self.download_port = download_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('',self.dht_port))

        self.peers = {}
        if id == None:
            SALT = b'ENotSewerSide-DHT-Service'+struct.pack('I',random.randint(0,10000))+struct.pack('I',random.randint(0,10000))
            self.id = reverse(hashlib.sha1(SALT).digest())
        else:
            self.id = id
        self.transactions = {}

    def get_transaction_id(self) ->bytes:
        start_transaction_id = random.randint(0,65535//2)
        transaction_id = struct.pack('H',start_transaction_id)
        res = self.transactions.get(transaction_id,False)
        while res != False and time.time()-res[0]<self.failtime:
            start_transaction_id +=1
            if start_transaction_id < 65536:
                transaction_id = struct.pack('H',start_transaction_id)
            else:
                transaction_id = struct.pack('I',start_transaction_id)
            res = self.transactions.get(transaction_id,False)
        return transaction_id

    def register_transaction(self,address:tuple,transaction_id:bytes,node=None,info_hash=None):
        id_address = transaction_id + bytes(address[0],'ascii')+bytes(str(address[1]),'ascii')
        if info_hash == None:
            self.transactions[id_address] = (time.time(),node,None)
        else:
            self.transactions[id_address] = (time.time(),node,info_hash)

    def ping(self,address:tuple):
        logging.debug("ping address:%s",str(address))
        transaction_id = self.get_transaction_id()
        data = {'t':transaction_id,
                'y':'q',
                'q':'ping',
                'a':{'id':self.id}}
        
        data_bencoded = Bencode.encode(data)
        self.socket.sendto(data_bencoded,address)
        return transaction_id

    def ping_answer(self,address:tuple,transaction_id:bytes):
        logging.debug("Sending ping packet:%s",str(address))
        data = {'t':transaction_id,
                'y':'r',
                'r':{'id':self.id
                     }
                }
        data_bencoded = Bencode.encode(data)
        self.socket.sendto(data_bencoded,address)


    def find_node(self,address:tuple,target_id:bytes):
        logging.debug("find_node address:%s,target_id:%s",str(address),str(target_id))
        transaction_id = self.get_transaction_id()
        data = {'t':transaction_id,
                'y':'q',
                'q':'find_node',
                'a':{'id':self.id,'target':target_id}}
        data_bencoded = Bencode.encode(data)
        self.socket.sendto(data_bencoded,address)
        return transaction_id

    def find_node_answer(self,address:tuple,transaction_id:bytes,nodes):
        logging.debug("Sending find_node packet:%s",str(address))
        data = {'t':transaction_id,
                'y':'r',
                'r':{'id':self.id,
                     'nodes':nodes
                    }
            }
        data_bencoded = Bencode.encode(data)
        self.socket.sendto(data_bencoded,address)

    def get_peers(self,address:tuple,info_hash:bytes):
        logging.debug("get_peers address:%s,info hash:%s",str(address),str(info_hash))
        transaction_id = self.get_transaction_id()
        data = {'t':transaction_id,
                'y':'q',
                'q':'get_peers',
                'a':{'id':self.id,'info_hash':info_hash}}
        data_bencoded = Bencode.encode(data)
        self.socket.sendto(data_bencoded,address)
        return transaction_id

    def get_peers_answer(self,address:tuple,transaction_id:bytes,token:bytes,payload):
        '''
        payload - values:[peer,peer]
        nodes - bytes()
        '''
        logging.debug("Sending get_peers address:%s,info hash:%s",str(address),str(payload))
        data = {'t':transaction_id,
                'y':'r',
                'r':{'id':self.id
                    }
                }
        if isinstance(payload,bytes):
            data['r']['nodes'] = payload
        else:
            data['r']['values'] = payload
        data_bencoded = Bencode.encode(data)
        self.socket.sendto(data_bencoded,address)
        return transaction_id

    def announce_peer(self,address:tuple,info_hash:bytes,token:bytes):
        logging.debug("announce_peer address:%s,info hash:%s",str(address),str(info_hash))
        transaction_id = self.get_transaction_id()
        data = {'t':transaction_id,
                'y':'q',
                'q':'announce_peer',
                'a':{'id':self.id,
                     'implied_port':1,
                     'info_hash':info_hash,
                     'port':0,
                     'token':token}}

        if self.download_port != None:
            data['a']['implied_port'] = 0
            data['a']['port'] = self.download_port

        data_bencoded = Bencode.encode(data)
        self.socket.sendto(data_bencoded,address)
        return transaction_id

    def send_error(self,address:tuple,code:int,msg:str,transaction_id:bytes):
        data = {'t':transaction_id,
                'y':'e',
                'e':[code,msg]}
        data_bencoded = Bencode.encode(data)
        self.socket.sendto(data_bencoded,address)

    def append_peers(self,info_hash:bytes,peers:list):
        if info_hash not in self.peers:
            self.peers[info_hash] = []
        for peer in peers:
            if peer not in self.peers[info_hash]:
                self.peers[info_hash].append(peer)

    def node_mistake(self,node:Node):
        node.fail()
        if node.fails >= self.max_fail:
            self.hashtable.remove(node)

    def dump(self,filename_hashtable='hashtable.dat',filename_peers='peers.dat'):
        logging.debug('dumping hashtable to file:%s',filename_hashtable)
        logging.debug('%s',filename_peers)

        file = open(filename_hashtable,'wb')
        pickle.dump(self.hashtable,file)
        file.close()

        file = open(filename_peers,'wb')
        pickle.dump(self.peers,file)
        file.close()

    def load(self,filename_hashtable='hashtable.dat',filename_peers='peers.dat'):
        
        file = open(filename_hashtable,'rb')
        self.hashtable = pickle.load(file)
        file.close()

        file = open(filename_peers,'rb')
        self.peers = pickle.load(file)
        file.close()
        

    def process_packet(self,data:bytes,from_address:tuple):
        '''
        returns code:int,msg:str,data
        '''
        logging.debug("received packet address:%s",str(from_address))

        #if from_address[0] == '127.0.0.1' and from_address[1] == self.dht_port:
        #    logging.warning('ERROR 203 DOS PACKET! address:%s data %s',str(address),str(from_address))
        #    return 203,'DOS PACKET!',None

        bc = Bencode.BencodeParser(data,False)
        try:
            data_decoded = bc.parse_Bencode()[0]
        except:
            logging.warning("ERROR 203 data:%s",str(data))
            return 203,'Malformed packet',None
        y = data_decoded.get('y',None)
        #transaction_id = data_decoded.get('t',None)

        if y == None:
            logging.warning("ERROR 203 data:%s",str(data))
            return 203,'Invalid arguments',None

        transaction_id = data_decoded.get('t',None)
        if transaction_id == None:
            logging.warning("ERROR 203 data:%s",str(data))
            return 203,'Invalid arguments',None

        if y == b'r':
            '''response'''

            calculated_transaction_id = transaction_id+bytes(from_address[0],'ascii')+bytes(str(from_address[1]),'ascii')
            transaction = self.transactions.pop(calculated_transaction_id,None)
            '''transaction: (time.time(),node/None,info_hash)'''

            payload = data_decoded.get('r',None)
                
            id = payload.get('id',None)#id from server
            if payload == None or transaction == None or id == None:
                logging.warning("ERROR 203 data:%s",str(data))
                return 203, 'Invalid arguments', transaction_id,b''

            if time.time()-transaction[0]>=self.failtime:
                logging.warning("ERROR 201 data:%s",str(data))
                if transaction[1] != None:
                    transaction[1].fail()
                return 201,'Transaction timed out',transaction_id,b''

            if transaction[1] == None:
                '''ping packet'''
                logging.debug("Ping packet")
                node = Node(from_address,id)
                self.hashtable.set(node,failtime=self.failtime)
                return 200,'Ok',None,b''
            else:
                if transaction[1].id != id:
                    return 203, 'Malformed packet',transaction_id,b''

            if 'token' in payload:
                '''get_peers packet'''
                logging.debug("Get peers packet")
                transaction[1].token = payload['token']
                if 'values' in payload:
                    logging.debug('Values in packet')
                    self.append_peers(transaction[2],payload['values'])
                    transaction[1].update_time()
                    
                if 'nodes' in payload:
                    logging.debug('Nodes in packet')
                    try:
                        nodes = parse_nodes_info(payload['nodes'])
                    except:
                        self.node_mistake(transaction[1])
                        logging.warning("ERROR 203 data:%s",str(data))
                        return 203,'Malformed packet',transaction_id

                    nodes_return = []
                    for node in nodes:
                        if node[1][0] == '0.0.0.0':
                            self.node_mistake(transaction[1])
                            continue
                        nodes_return.append(Node(node[1],node[0]))
                        self.hashtable.set(nodes_return[-1],failtime=self.failtime)
                    
                    transaction[1].update_time()
                    return 200,'Ok',nodes_return,transaction[2]
                if 'values' not in payload and 'nodes' not in payload:
                    self.node_mistake(transaction[1])
                    logging.warning("ERROR 203 data:%s",str(data))
                    return 203,'Protocol Error',transaction_id,b''
                return 200,'Ok',None,b''
            elif 'nodes' in payload:
                '''find_node packet'''
                logging.debug("Find node packet")
                try:
                    nodes = parse_nodes_info(payload['nodes'])
                except:
                    self.node_mistake(transaction[1])
                    logging.warning("ERROR 203 data:%s",str(data))
                    return 203,'Malformed packet',transaction_id,b''
                nodes_return = []
                for node in nodes:
                    if node[1][0] == '0.0.0.0':
                        self.node_mistake(transaction[1])
                        continue
                    nodes_return.append(Node(node[1],node[0]))
                    self.hashtable.set(nodes_return[-1],failtime=self.failtime)
                transaction[1].update_time()
                return 200,'Ok',nodes_return,transaction[2]
            else:
                '''announce_peer packet'''
                transaction[1].update_time()
                logging.debug("Announce peer packet")
                return 200,'Ok',None,b''
        elif y == b'q':
            '''query'''

            query = data_decoded.get('q',None)
            payload = data_decoded.get('a',None)
            if query == None or payload == None:
                logging.warning("ERROR 203 data:%s",str(data))
                return 203,'Invalid arguments',transaction_id,b''
            id = payload.get('id',None)
            if id == None:
                logging.warning("ERROR 203 data:%s",str(data))
                return 203,'Invalid arguments',transaction_id,b''

            if query == b'ping':
                logging.debug("Get ping request")
                self.hashtable.set(Node(from_address,id))
                self.ping_answer(from_address,transaction_id)
                return 200,'Ok',None,b''
            elif query == b'find_node':
                logging.debug("Get find_node request")
                node = self.hashtable.find_node(id)
                if 'target' not in payload:
                    if isinstance(node,Node):
                        self.node_mistake(node)
                    logging.warning("ERROR 203 data:%s",str(data))
                    return 203,'Ivalid arguments',transaction_id,b''
                if isinstance(node,list):
                    node = Node(from_address,id)
                    self.hashtable.set(node)
                else:
                    node.update_time()
                nodes = self.hashtable.find_node(payload['target'])
                if isinstance(nodes,Node):
                    self.find_node_answer(from_address,transaction_id,nodes.get_compact_info())
                else:
                    dt = b''
                    for node in nodes:
                        dt += node.get_compact_info()
                    self.find_node_answer(from_address,transaction_id,dt)
                return 200,'Ok',None,b''
            elif query == b'get_peers':
                logging.debug("Get get_peers request")
                node = self.hashtable.find_node(id)
                if 'info_hash' not in payload:
                    if isinstance(node,Node):
                        self.node_mistake(node)
                    logging.warning("ERROR 203 data:%s",str(data))
                    return 203,"Malformed packet",transaction_id,b''
                
                if isinstance(node,list):
                    node = Node(from_address,id)
                    self.hashtable.set(node)
                else:
                    node.update_time()
                token = node.issue_token()
                peers = self.peers.get(payload['info_hash'],None)
                if peers != None:
                    self.get_peers_answer(from_address,transaction_id,token,peers)
                else:
                    bucket_index = self.hashtable.get_bucket_index(payload['info_hash'])
                    nodes = self.hashtable.get_bucket(bucket_index)
                    dt = b''
                    for node in nodes:
                        dt += node.get_compact_info()
                    self.get_peers_answer(from_address,transaction_id,token,dt)
                return 200,'Ok',None,b''
            elif query == b'announce_peer':
                logging.debug("Get announce_peer request")
                node = self.hashtable.find_node(id)
                if isinstance(node,list):
                    logging.warning("ERROR 201 data:%s",str(data))
                    return 201,'Not found id in routetable',transaction_id,b''

                node.update_time()

                token = payload.get('token',None)
                if token == None:
                    logging.warning("ERROR 203 data:%s",str(data))
                    self.node_mistake(node)
                    return 203,'No token',transaction_id,b''

                if token != node.issued_token:
                    logging.warning("ERROR 203 data:%s",str(data))
                    self.node_mistake(node)
                    return 203,'Wrong token',transaction_id,b''

                info_hash = payload.get('info_hash',None)
                if info_hash == None:
                    logging.warning("ERROR 203 data:%s",str(data))
                    self.node_mistake(node)
                    return 203,'Malformed packet',transaction_id,b''

                port = from_address[1]
                implied_port = payload.get('implied_port',None)
                if implied_port == None or implied_port == 0:
                    port = payload.get('port',None)
                    if port == None:
                        logging.warning("")
                        self.node_mistake(node)
                        return 203,'Malformed packet',transaction_id,b''

                if port > 65535:
                    self.node_mistake(node)
                    logging.warning('ERROR 203 WRONG PORT! address:%s data:%s',str(from_address),str(data))
                    return 203,'Wrong port',transaction_id,b''

                node.update_time()

                if info_hash not in self.peers:
                    self.peers[info_hash] = []

                encoded_address = struct.pack('>I',encode_ip(from_address[0]))+struct.pack('>H',port)
                if encoded_address not in self.peers[info_hash]:
                    self.peers[info_hash].append(encoded_address)
                self.ping_answer(from_address,transaction_id)
                return 200,'Ok',None,b''
            
            else:
                node = self.hashtable.find_node(id)
                if isinstance(node,Node):
                    self.node_mistake(node)
                logging.warning("ERROR 204 data:%s",str(data))
                return 204,'Unknown method',transaction_id,b''
        elif y==b'e':
            logging.warning('Error from server: %s',str(data))
            return 200,'Error',None,b''


    def start(self,torrents:list,packets_bunch=10,all_gets=50,ask_for_peers=60,dumping_period=60,max_offset=8,ask_all_timeout=300,delete_banch=100):
        global ENTRYPOINTS
        try:
            self.load()
        except Exception as e:
            self.socket.settimeout(15)
            for entrypoint in ENTRYPOINTS:
                logging.debug('Pinging %s',str(entrypoint))
                node = Node(entrypoint)
                self.ping(entrypoint)
                try:
                    data = self.socket.recv(2048)
                except:
                    logging.warning("No response from node")
                    continue
                logging.debug("Ping packet received")
                bc = Bencode.BencodeParser(data,False)
                data_parsed = bc.parse_Bencode()[0]
                node.id = data_parsed['r']['id']
                self.hashtable.set(node)

        self.socket.setblocking(0)


        last_asked_peers = [0]*len(torrents)
        torrent_counter = 0
        
        started_time = time.time()
        first_start = True
        last_dump = time.time()

        last_all_asked = time.time()

        while True:
            parsed_data = None
            counter = packets_bunch
            while counter != 0:
                counter -= 1
                try:
                    data,from_address = self.socket.recvfrom(4096)
                except Exception as e:
                    break

                if (from_address[0] == '127.0.0.1'and from_address[1]==self.dht_port)\
                   or from_address[0] == '0.0.0.0':
                    logging.warning('ERROR DOS PACKET! %s %s',str(from_address),str(data))
                    continue

                logging.debug('Accepted packet, starting processing...')
                parsed_data = self.process_packet(data,from_address)
                

                if parsed_data[0] != 200:
                    self.send_error(from_address,parsed_data[0],parsed_data[1],parsed_data[2])
                elif isinstance(parsed_data[2],list):
                    logging.debug('Got %d nodes in answer',len(parsed_data[2]))
                    for node in parsed_data[2]:
                        transaction_id = self.get_peers(node.address,parsed_data[3])
                        self.register_transaction(node.address,transaction_id,node,parsed_data[3])

            if (all_gets>0 and (parsed_data!=None and isinstance(parsed_data[2],list))) or first_start:
                last_all_asked = time.time()
                first_start = False
                logging.debug('Asking all nodes %s',str(all_gets))
                for bucket in self.hashtable.buckets:
                    for node in bucket:
                        info_hash = torrents[torrent_counter].info_hash
                        transaction_id = self.get_peers(node.address,info_hash)
                        self.register_transaction(node.address,transaction_id,node,info_hash)
                all_gets-=1

            elif all_gets==0 and\
                time.time() - last_asked_peers[torrent_counter]>= ask_for_peers:

                last_asked_peers[torrent_counter] = time.time()
                info_hash = torrents[torrent_counter].info_hash
                logging.debug('Getting peers for info_hash:%s',str(info_hash))
                bucket_id = self.hashtable.get_bucket_index(info_hash)
                left_offset = max_offset#max_offset
                right_offset = max_offset#max_offset
                if bucket_id+right_offset >= len(self.hashtable.buckets)-1:
                    right_offset = len(self.hashtable.buckets)-1 - bucket_id
                if bucket_id-left_offset < 0:
                    left_offset = bucket_id

                start = bucket_id - left_offset

                for index in range(start,bucket_id+right_offset):
                    bucket = self.hashtable.get_bucket(index)
                    for node in bucket:
                        transaction_id = self.get_peers(node.address,info_hash)
                        self.register_transaction(node.address,transaction_id,node,info_hash)
        
            elif time.time()-started_time>=self.failtime:
                logging.debug('Starting cleaning process')
                started_time = time.time()
                transactions_to_delete = []
                counter = delete_banch
                for key,item in self.transactions.items():
                    if item[0]>=self.failtime:
                        transactions_to_delete.append(key)
                        counter -= 1
                    if counter == 0:
                        break

                logging.debug('Fetched %s transactions',str(len(transactions_to_delete)))
                for key in transactions_to_delete:
                    node = self.transactions[key][1]
                    node.alive(self.failtime)
                    if node.fails >= self.max_fail:
                        self.hashtable.remove(node)
                    del self.transactions[key]
            
            torrent_counter += 1
            if torrent_counter >= len(torrents):
                torrent_counter = 0
            if len(last_asked_peers) != len(torrents):
                last_asked_peers = [0]*len(torrents)

            if time.time()-last_all_asked>ask_all_timeout:
                first_start = True
                all_gets = 1

            if time.time()-last_dump > dumping_period:
                last_dump = time.time()
                self.dump()
            
            time.sleep(0.5)

            



            
                

                    



                        


                




                



    



if __name__ == '__main__':
    
    hash = hashlib.sha1(b'123').digest()
    id = get_id(hash)
    print(id)