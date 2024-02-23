import sqlite3

class CRUD:
    
    def __init__(self):
        self.conn = sqlite3.connect('dev_data.db')
        self.cursor = self.conn.cursor()
        
    def start(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS beacons (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ssid TEXT NOT NULL,
                bssid TEXT NOT NULL, channel INTEGER NOT NULL,
                frequency INTEGER NOT NULL, oui TEXT NOT NULL,
                retry_status TEXT NOT NULL, ibss_status TEXT NOT NULL, status CHAR NOT NULL,
                pwr INTEGER, Enc TEXT, Auth TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ssid TEXT NOT NULL, bssid TEXT NOT NULL,
                channel INTEGER NOT NULL, frequency INTEGER NOT NULL,
                oui TEXT NOT NULL, retry_status TEXT NOT NULL,
                ibss_status TEXT NOT NULL, pwr INTEGER, Enc TEXT, Auth TEXT
            )
        ''')
        print('the jurney is begin')
    
    def load_beacon(self):
        self.cursor.execute("SELECT * FROM beacons")
        return self.cursor.fetchall()
    
    def load_whitelist(self):
        self.cursor.execute("SELECT * FROM whitelist")
        return self.cursor.fetchall()
        
    def delete_selected(self, ids):
        self.cursor.execute("DELETE FROM beacons WHERE id IN ({})".format(','.join(ids)))
        self.conn.commit()
    
    def delete_selected2(self, ids):
        self.cursor.execute("DELETE FROM whitelist WHERE id IN ({})".format(','.join(ids)))
        self.conn.commit()
        
    def add_to_whitelist(self, iid):
        self.cursor.execute('''INSERT INTO whitelist (ssid, bssid, channel, frequency, oui, retry_status, ibss_status) 
        SELECT ssid, bssid, channel, frequency, oui, retry_status, ibss_status FROM beacons WHERE id = ? ''', (iid,))
        self.conn.commit()
    
    def save(self, data):
        self.cursor.executemany("INSERT INTO beacons (ssid, bssid, channel, frequency, oui, retry_status, ibss_status, pwr, enc, auth, status) VALUES (?,?,?,?,?,?,?,?,?,?,?)", data)
        self.conn.commit()
    
    def get_ap(self, ids):
        self.cursor.execute("SELECT * FROM beacons WHERE id = ? ", (ids,))
        return self.cursor.fetchall()
        
    def empty_table(self):
        cmd = 'DELETE FROM beacons'   
        self.cursor.execute(cmd)
        
    def cek_1(self):
        # Check rogue AP with same SSID and different MAC
        data = set()
        status = False
        cmd = "select * from beacons as s where s.ssid in (select ssid from whitelist) and s.bssid not in (select w.bssid from whitelist as w where s.ssid = w.ssid)"
        self.cursor.execute(cmd)
        if self.cursor.rowcount > 0:
            data = cursor.fetchall()
            status = True
        return data, status
        
    def cek_2(self):
        # Check rogue AP with same SSID and MAC and different other attribute (such as: channel, Auth, Enc)    
        data = set()
        status = False
        cmd = "select distinct * from beacons as s inner join whitelist as w on s.ssid = w.ssid and s.bssid = w.bssid where s.channel != w.channel \
            or s.Enc != w.Enc or s.Auth != w.Auth"
        self.cursor.execute(cmd)
        if self.cursor.rowcount > 0:
            data = cursor.fetchall()
            status = True
        return data, status
    
    def cek_3(self):
        return
        
    def __del__(self):
        self.conn.close()
