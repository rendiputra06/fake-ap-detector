from scapy.all import *
from . crud import CRUD
from PyQt5 import QtCore, QtWidgets
from . color import Color
import time
import os
from subprocess import *
from netaddr import *
import sys, getopt
import datetime

class Scan(QtCore.QThread):
    progressChanged = QtCore.pyqtSignal(int)
    
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.beacons = []
        self.seen_bssids = set()
        self.i = 0
        
    def split_crypto(self, crypto):
        con = list(crypto)
        text = con[0]
        cek = text.split("/")
        enc = cek[0]
        auth = ''
        try:
            auth = cek[1]
        except:
            auth = ''
	
        return enc, auth
        
    def run(self):
        model = CRUD()
        # hapus isi data beacons
        model.empty_table()
        self.beacons = []
        self.seen_bssids = set()
        
        def beacon_callback(pkt):
            self.i += 1
            self.progressChanged.emit(self.i)
            try:
                if pkt.haslayer(Dot11Beacon):
                    ssid = pkt[Dot11Elt].info.decode()
                    bssid = pkt[Dot11].addr3
                
                    # check if the BSSID has already been seen
                    if bssid in self.seen_bssids:
                        return
                    else:
                        self.seen_bssids.add(bssid)
                        
                    channel = int(ord(pkt[Dot11Elt:3].info))
                    frequency = pkt.getlayer(Dot11).getfieldval("subtype")
                    oui = bssid[:8]
                    retry_bit = (pkt[Dot11].FCfield & 0b10) >> 1
                    if retry_bit:
                        retry_status = "Retransmission"
                    else:
                        retry_status = "Not a retransmission"
                    ibss_bit = (pkt[Dot11].FCfield & 0b100) >> 2
                    if ibss_bit:
                        ibss_status = "IBSS"
                    else:
                        ibss_status = "BSS"
                
                    #get more data
                    pwr = pkt.dBm_AntSignal
                    enc = None
                    auth = None
                    
                    # extract network stats
                    stats = pkt[Dot11Beacon].network_stats()
                    crypto = stats.get("crypto")
                    enc, auth = self.split_crypto(crypto)
                    
                    dt = [ssid, bssid, channel, frequency, oui, retry_status, ibss_status, pwr, enc, auth]
                    more = [ssid, bssid, pwr, enc, auth]
                    print(dt)
                    dt.append('0')
                    self.beacons.append(dt)
            except Exception as e:
                print(e)
                
        sniff(iface=self.iface, prn=beacon_callback, count=100, filter="type mgt subtype beacon")
        print('Sniffing Selesai')
        model.save(self.beacons)
        self.progressChanged.emit(-1)
       
        
class Worker(QtCore.QThread):
    progressChanged = QtCore.pyqtSignal(int)
    def __init__(self, iface):
        super().__init__()
        self.warna = Color()
        self.iface = iface
        
    def run(self):
        try:
            os.system('rm file/scan/hasil-scan-01.*')
        except:
            print(self.warna.FAIL + self.warna.BOLD + "Unexpected error during removing old 'out.csv-01': {}\n".format(sys.exc_info()[0]) + self.warna.ENDC)
        # Scanning for available SSIDs
        print("\n\n=======================")
        print("SCANNING FOR WIRELESS NETWORKS USING = " + self.iface)
        print("\n\n")
        
        try:
            airodump = Popen(["airodump-ng", "--output-format", "csv",  "-w", "file/scan/hasil-scan", self.iface])
            for count in range(10):
                self.progressChanged.emit(count)
                self.sleep(1)
            self.progressChanged.emit(-1)
            airodump.terminate()
        except Exception as e:
            print(e)
            print(self.warna.FAIL + self.warna.BOLD + "Unexpected error during scanning for available SSIDs: {}\n".format(sys.exc_info()[0]) + self.warna.ENDC)
        
class Security(QtCore.QThread):
    progressChanged = QtCore.pyqtSignal(int)
    def __init__(self):
        super().__init__()
        
    def run(self):
        model = CRUD()
        data1, status1 = model.cek_1()
        if status1:
            print('ada ap yang namanya sama dengan yg di whitelist')
            print(data1)

        self.sleep(1)
        self.progressChanged.emit(-1)
        print('Security Selesai, tidak ada ap yang mencurigakan')
