from scapy.all import *
from . crud import CRUD
from PyQt5 import QtCore

class Scan(QtCore.QThread):
    progressChanged = QtCore.pyqtSignal(int)
    
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.beacons = []
        self.seen_bssids = set()
        
    def run(self):
        def beacon_callback(pkt):
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
                self.beacons.append([ssid, bssid, channel, frequency, oui, retry_status, ibss_status])

        sniff(iface=self.iface, prn=beacon_callback, count=50, filter="type mgt subtype beacon")
        model = CRUD()
        model.save(self.beacons)
        self.progressChanged.emit(-1)
