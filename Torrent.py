import Bencode
import requests#rewrite for sockets
import socket
import random
import string
import time
import hashlib
import struct
import threading
import TrackerHandler

import DHT
import logging

logging.basicConfig(filename='Torrent.log',filemode='w', level=logging.DEBUG)




start_port = 6881


def get_peer_id():
    to_return = 'EnotTor'
    for i in range(13):
        to_return += random.choice(string.ascii_letters)
    return to_return



class Tracker:
    def __init__(self,address:tuple,protocol:str,host=''):
        self.address = address
        self.protocol = protocol
        self.interval = 0
        self.last_announce = 0
        self.working = True

        
        
        if self.protocol == 'ipv4':
            self.host = host
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(0)
            self.connection_id = None #for ipv4/6
            self.time_got_connection_id = 0
            self.max_retries = 8
            
        

    def connect(self,torrent):
        # only for ipv4/ipv6
        # only sends connect request to tracker
        if self.protocol == 'ipv4':
            protocol_id = struct.pack('!Q',0x41727101980)

            timeout_koef = 0
            transaction_id = random.randint(0,1000000)
            
            while timeout_koef <= self.max_retries:
                data = None
                
                #last_transaction_id = random.randint(0,1000000)
                packet = protocol_id + struct.pack('>I',0) + struct.pack('>I',transaction_id)
                self.socket.sendto(packet,self.address)
                
                try:
                    data, server = self.socket.recvfrom(4096)
                    if len(data)<16:
                        timeout_koef += 1
                        time.sleep(15*(2**timeout_koef))
                    else:
                        if self.parse_packet(data,transaction_id) != False:
                            break
                except Exception as e:
                    time.sleep(15*(2**timeout_koef))
                    timeout_koef += 1
                    #print(timeout_koef)#!!!!!!!!!!!!!


            #return self.parse_packet(data,transaction_id)

    def parse_packet(self,data,transaction_id):
        if data == None:
            self.working = False
        else:
            if struct.unpack('>I',data[4:8])[0] == transaction_id:
                action = struct.unpack('>I',data[0:4])[0]
                if action == 0:
                    self.connection_id = struct.unpack('>Q',data[8:16])[0]
                    self.time_got_connection_id = time.time()
                    return None
                elif action == 1:
                    self.interval = struct.unpack('>I',data[8:12])[0]
                    to_return = []
                    n_seeders = struct.unpack('>I',data[16:20])[0]
                    for i in range(n_seeders):
                        to_return.append((decode_ip(struct.unpack('>I',data[20 + 6 * i:24 + 6 * i])[0]),struct.unpack('>H',data[24 + 6 * i:26+6*i])[0]))
                    return to_return
            else:
                return False


    def append_peers(self,torrent,peers):
        if type(peers) != list:
            return None
        for peer in peers:
            torrent.glb_lock.acquire()
            if peer not in torrent.seeders:   
                
                torrent.seeders.append(peer)
            torrent.glb_lock.release()
       
    def announce(self,torrent):
        # Torrent is Torrent obj
        #sets interval for the tracker, returns seeders
        if self.protocol == 'http':
            try:
                response = requests.get(self.address,params={'info_hash':torrent.info_hash,
                                                            'peer_id':torrent.peer_id,
                                                            'port':start_port,
                                                            'uploaded':torrent.uploaded,
                                                            'downloaded':torrent.downloaded,
                                                            'left':torrent.left,
                                                            'compact':1})
            except Exception as e:
                self.working = False
                return None
            self.last_announce = time.time()
            decoded = Bencode.BencodeParser(response.content,filename = False).parse_Bencode()
            peers = peers_unpack(decoded[0]['peers'])
            #decoded[0]['peers'] = peers
            if 'min interval' in decoded[0].keys():
                self.interval = decoded[0]['min interval']
            else:
                self.interval = decoded[0]['interval']
            self.append_peers(torrent,peers)

        elif self.protocol == 'ipv4':
            if time.time()-self.time_got_connection_id > 60:
                self.connect(self.socket)
            
            if self.connection_id == None:
                return None

            timeout_koef = 0
            transaction_id = random.randint(0,1000000)

            packet = struct.pack('>Q',self.connection_id) 
            packet += struct.pack('>I',1)
            packet += struct.pack('>I',transaction_id)
            packet += torrent.info_hash+bytes(torrent.peer_id,'ascii')
            packet += struct.pack('>Q',torrent.downloaded)
            packet += struct.pack('>Q',torrent.left)
            packet += struct.pack('>Q',torrent.uploaded)
            packet += struct.pack('>I',0)
            packet += struct.pack('>I',0)
            packet += struct.pack('>I',0)
            packet += struct.pack('>i',-1)
            packet += struct.pack('>H',start_port)


            while timeout_koef <= self.max_retries:
                data = None
                self.socket.sendto(packet,self.address)
                self.last_announce = time.time()
                try:
                    data, server = self.socket.recvfrom(4096)
                    if len(data)<8:
                        time.sleep(15*(2**timeout_koef))
                        timeout_koef += 1
                        #time.sleep(15*(2**timeout_koef))
                    else:
                        peers = self.parse_packet(data,transaction_id)
                        if peers != False:
                            self.append_peers(torrent,peers)
                            break
                except:
                    time.sleep(15*(2**timeout_koef))
                    timeout_koef += 1
                    #print(timeout_koef)#!!!!!!!!
            





def parse_tracker(address_raw:bytes):
    address_decoded = address_raw.decode('utf-8')
    if address_decoded[:3] == 'udp':
        address_port = address_decoded[6:]
        offset = address_port.find('/')
        if offset != -1:
            address_port = address_port[:offset]

        offset = address_port.find('[')
        if offset != -1:#ipv6
            soffset = address_port.find(']')
            address = address_port[offset+1:soffset]
            port = int(address_port[soffset+2:])
            return Tracker((address,port),'ipv6')
        else:#may be ipv4
            splitted_data = address_port.split(':')
            address = splitted_data[0]
            host = address
            port = int(splitted_data[1])
            buf = address.split('.')
            if len(buf) == 4:
                for elem in buf:
                    try:
                        int(elem)
                    except:
                        try:
                            address = socket.gethostbyname(address)
                        except:
                            return None
                        break
            else:
                try:
                    address = socket.gethostbyname(address)
                except:
                    return None
            return Tracker((address,port),'ipv4',host)
    elif address_decoded[:4] == 'http':
        return Tracker(address_decoded,'http')
    







class Torrent:
    def __init__(self,torrent_file:str):
        ben = Bencode.BencodeParser(torrent_file)
        self.parsed_info = ben.parse_Bencode()

        self.info_hash = hashlib.sha1(Bencode.encode(self.parsed_info[0]['info'])).digest()

        self.total_size = 0
        files = self.parsed_info[0]['info'].get('files',False)
        if files != False:
            for file in files:
                self.total_size += file['length']
        else:
            self.total_size = self.parsed_info[0]['info']['length']
        self.downloaded = 0
        self.uploaded = 0
        self.peer_id = requests.utils.quote(get_peer_id())
        self.left = self.total_size
        self.seeders = []
        self.trackers = []
        if 'announce-list' in self.parsed_info[0].keys():
            for tr in self.parsed_info[0]['announce-list']:
                tracker = parse_tracker(tr[0])
                if tracker != None:
                    self.trackers.append(tracker)
        else:
            tracker = parse_tracker(self.parsed_info[0]['announce'])
            if tracker != None:
                self.trackers.append(tracker)
            else:
                raise Exception("Can't find available trackers")
        self.glb_lock = threading.Lock()
        self.tracker_handler = threading.Thread(target=TrackerHandler.handler,args=(self,))
    
    def start(self):
        self.tracker_handler.start()
        while True:
            time.sleep(10)
            #self.glb_lock.acquire()
            #print(self.seeders)
            #self.glb_lock.release()
        #self.tracker_handler.join()#!!!!!!


   
 
def decode_ip(encoded_ip:int):
    ip_decoded = ''

    for i in range(3,-1,-1):
        num = encoded_ip//(256**i)
        encoded_ip = encoded_ip - num*(256**i)
        ip_decoded += str(num)+'.'
    return ip_decoded[0:len(ip_decoded)-1]


def peers_unpack(data:bytes):
    if len(data) % 6 != 0:
        raise Exception('Every peer must be encoded with 6 bytes')
    to_return = []
    for offset in range(0,len(data),6):
        ip_encoded = decode_ip(struct.unpack('>I',data[offset:offset+4])[0])
        port = struct.unpack('>H',data[offset+4:offset+6])[0]
        to_return.append((ip_encoded,port))
    return to_return




if __name__ == '__main__':
    
    

    torrent1 = Torrent('test.torrent')
    torrent2 = Torrent('test2.torrent')
    torrent3 = Torrent('test3.torrent')
    torrent4 = Torrent('test4.torrent')
    #torrent5 = Torrent('Vampire-The-Masquerade-Bloodlines-v1.0-10.6.torrent')
    torrent6 = Torrent('Mafia-2-Digital-Deluxe-Edition-by-Igruha.torrent')
    torrent7 = Torrent("Vampire-The-Masquerade-Bloodlines-v1.0-10.6.torrent")
    
    dht = DHT.DHT(dht_port=6882)
    buf = [torrent1,torrent2,torrent3,torrent4,torrent6,torrent7] 

    dht_thread = threading.Thread(target = DHT.DHT.start,args=(dht,buf))#,0.5,70,parse_timeout,10,-1))
    dht_thread.start()

    #time.sleep(60)
    #buf.append(torrent5)
    #buf.append(torrent6)
    dht_thread.join()
    #for tracker in torrent.trackers:
    #    print(tracker.address)
    #    tracker.announce(torrent)
    #    print(torrent.seeders)
    #    #print(1)
    print(1)
    torrent.start()


