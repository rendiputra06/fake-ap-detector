from PyQt5 import QtCore, QtGui, QtWidgets
import oop.crud as init
import oop.scan as scanning
import oop.splash as sp

class Window(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.model = init.CRUD()
        # self.model.start()
        self.scan = scanning.Scan('wlan0')
        self.setWindowTitle("Evil AP Defender")
        # Create the table widget
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["ID", "SSID", "BSSID", "Chan", "Freq", "OUI", "Retry Status", "IBSS Status", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        #self.setCentralWidget(self.table)
        self.table.cellDoubleClicked.connect(self.fill_form)

        self.table2 = QtWidgets.QTableWidget()
        self.table2.setColumnCount(8)
        self.table2.setHorizontalHeaderLabels(["ID", "SSID", "BSSID", "Chan", "Freq", "OUI", "Retry Status", "IBSS Status"])
        self.table2.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table2.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table2.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        #self.setCentralWidget(self.table2)
        
        
        # Create the "Select All" button
        self.select_all_button = QtWidgets.QPushButton("Select All")
        self.select_all_button.clicked.connect(self.table.selectAll)

        # Create the "Delete" button
        self.delete_button = QtWidgets.QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_selected)

        # Create the "Whitelist" button
        self.whitelist_button = QtWidgets.QPushButton("Whitelist")
        self.whitelist_button.clicked.connect(self.add_to_whitelist)
        
        # Create the "Scan" button
        self.scan_button = QtWidgets.QPushButton("Scan")
        self.scan_button.clicked.connect(self.airodump_ap)

        # Create the "Select All" button
        self.select_all_button2 = QtWidgets.QPushButton("Select All")
        self.select_all_button2.clicked.connect(self.table2.selectAll)

        # Create the "Delete" button
        self.delete_button2 = QtWidgets.QPushButton("Delete")
        self.delete_button2.clicked.connect(self.delete_selected2)
        
        # Add the buttons to the beacon table
        self.button_layout = QtWidgets.QHBoxLayout()
        self.button_layout.addWidget(self.select_all_button)
        self.button_layout.addWidget(self.delete_button)
        self.button_layout.addWidget(self.scan_button)
        self.button_layout.addWidget(self.whitelist_button)
        
        # Add the buttons to the whitelist table
        self.button_layout2 = QtWidgets.QHBoxLayout()
        self.button_layout2.addWidget(self.select_all_button2)
        self.button_layout2.addWidget(self.delete_button2)

        self.main_layout = QtWidgets.QVBoxLayout()
        self.main_layout.addWidget(QtWidgets.QLabel("Wireless Networks Found:"))
        self.main_layout.addWidget(self.table)
        self.main_layout.addLayout(self.button_layout)
        self.main_layout.addWidget(QtWidgets.QLabel("Whitelisted Access Points:"))
        self.main_layout.addWidget(self.table2)
        self.main_layout.addLayout(self.button_layout2)
        
        self.ssid_edit = QtWidgets.QLineEdit()
        self.bssid_edit = QtWidgets.QLineEdit()
        self.channel_edit = QtWidgets.QLineEdit()
        self.freq_edit = QtWidgets.QLineEdit()
        self.iou_edit = QtWidgets.QLineEdit()
        self.retry_edit = QtWidgets.QLineEdit()
        self.ibss_edit = QtWidgets.QLineEdit()
        self.power_edit = QtWidgets.QLineEdit()
        self.enc_edit = QtWidgets.QLineEdit()
        self.auth_edit = QtWidgets.QLineEdit()
        
        self.form_layout = QtWidgets.QFormLayout()
        self.form_layout.addWidget(QtWidgets.QLabel("Detail Data Access Point:"))
        self.form_layout.addRow("SSID :", self.ssid_edit)
        self.form_layout.addRow("BSSID :", self.bssid_edit)
        self.form_layout.addRow("Channel :", self.channel_edit)
        self.form_layout.addRow("Frequency :", self.freq_edit)
        self.form_layout.addRow("IOU :", self.iou_edit)
        self.form_layout.addRow("Retry Status :", self.retry_edit)
        self.form_layout.addRow("IBSS Status :", self.ibss_edit)
        self.form_layout.addRow("Power :", self.power_edit)
        self.form_layout.addRow("Enc :", self.enc_edit)
        self.form_layout.addRow("Auth :", self.auth_edit)
        
        #self.main_layout.addLayout(self.form_layout)
        
        self.split_layout = QtWidgets.QHBoxLayout()
        self.split_layout.addLayout(self.main_layout, 2)
        self.split_layout.addLayout(self.form_layout, 1)
        
        self.central_widget = QtWidgets.QWidget()
        self.central_widget.setLayout(self.split_layout)
        self.setCentralWidget(self.central_widget)

        # Load the beacons from the database
        self.load_beacons()

    def load_beacons(self):
        beacons = self.model.load_beacon()
        self.table.setRowCount(len(beacons))
        for i, b in enumerate(beacons):
            for j, val in enumerate(b):
                self.table.setItem(i, j, QtWidgets.QTableWidgetItem(str(val)))
    
    def load_whitelist(self):
        beacons = self.model.load_whitelist()
        self.table2.setRowCount(len(beacons))
        for i, b in enumerate(beacons):
            for j, val in enumerate(b):
                self.table2.setItem(i, j, QtWidgets.QTableWidgetItem(str(val)))

    def delete_selected(self):
        selected = self.table.selectedIndexes()
        if not selected:
            QtWidgets.QMessageBox.warning(self, "Warning", "No rows selected.")
            return
        ids = [self.table.item(i.row(), 0).text() for i in selected]
        self.model.delete_selected(ids)
        self.load_beacons()

    def delete_selected2(self):
        selected = self.table2.selectedIndexes()
        if not selected:
            QtWidgets.QMessageBox.warning(self, "Warning", "No rows selected.")
            return
        ids = [self.table2.item(i.row(), 0).text() for i in selected]
        self.model.delete_selected2(ids)
        self.load_whitelist()
        
    def add_to_whitelist(self):
        selected = self.table.selectedIndexes()
        if not selected:
            QtWidgets.QMessageBox.warning(self, "Warning", "No rows selected.")
            return
        iid = self.table.item(selected[1].row(), 0).text()
        print(iid)
        self.model.add_to_whitelist(iid)
        self.load_whitelist()
        QtWidgets.QMessageBox.information(self, "Info", "BSSID added to whitelist.")
    
    def scan_ap(self):
        print('Sniffing Start')
        splash.show()
        scan.start()
        
    def airodump_ap(self):
        print('Airodump Start')
        splash.show()
        worker.start()
        
    def security(self):
        print('Security Start')
        splash.show()
        st = secur.start()
    
    def fill_form(self, row, column):
        ids = self.table.item(row, 0).text()
        aps = self.model.get_ap(ids)
        print(aps[0])
        self.ssid_edit.setText(str(aps[0][1]))
        self.bssid_edit.setText(str(aps[0][2]))
        self.channel_edit.setText(str(aps[0][3]))
        self.freq_edit.setText(str(aps[0][4]))
        self.iou_edit.setText(str(aps[0][5]))
        self.retry_edit.setText(str(aps[0][6]))
        self.ibss_edit.setText(str(aps[0][7]))
        self.power_edit.setText(str(aps[0][9]))
        self.enc_edit.setText(str(aps[0][10]))
        self.auth_edit.setText(str(aps[0][11]))
        
if __name__ == '__main__':
    app = QtWidgets.QApplication([])
    window = Window()
    window.resize(1280, 720)
    window.show()
    # load data whitelist
    window.load_whitelist()
    splash = sp.SplashScreen('loading.gif', QtCore.Qt.WindowStaysOnTopHint)
    
    # 1 Scan menggunakan airodump-ng
    worker = scanning.Worker('wlan0')
    worker.progressChanged.connect(splash.updateProgress)
    worker.finished.connect(
        lambda: (splash.finish(window), window.scan_ap()))
    # 2 Scan Menggunakan Scapy    
    scan = scanning.Scan('wlan0')
    scan.progressChanged.connect(splash.updateProgress)
    scan.finished.connect(
        lambda: (splash.finish(window), window.security()))
    # 3 Periksa Hasil Scanning yg sudah di simpan di sqlite
    secur = scanning.Security()
    secur.progressChanged.connect(splash.updateProgress)
    secur.finished.connect(
        lambda: (splash.finish(window), window.load_beacons()))
        
    app.exec_()
