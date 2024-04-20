import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem, 
    QVBoxLayout, QWidget, QPushButton, QComboBox, QLabel, 
    QHBoxLayout, QStatusBar
)
from PyQt5.QtCore import pyqtSlot, QThread, pyqtSignal
from scapy.all import ARP, sniff, get_if_list
from scapy.arch.windows import get_windows_if_list

import subprocess
import re

class ArpSniffer(QThread):
    new_entry = pyqtSignal(str, str, str, str)  # Adjusted to include old MAC address

    def __init__(self, interface=None, existing_arp_table=None):
        super(ArpSniffer, self).__init__()
        self.interface = interface
        self.existing_arp_table = existing_arp_table or {}
        self.running = True

    def run(self):
        try:
            sniff(prn=self.process_packet, filter="arp", store=0, iface=self.interface, stop_filter=self.stop_sniffing)
        except Exception as e:
            print(f"Error starting the sniffer: {str(e)}")

    def process_packet(self, pkt):
        if pkt[ARP].op == 2:  # Is it an ARP response?
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc.replace('-', ':').upper()  # Ensure MAC is in the correct format
            # Emit signal only if IP is new or MAC has changed
            if src_ip not in self.existing_arp_table:
                self.new_entry.emit(src_ip, src_mac, 'New', '')
                self.existing_arp_table[src_ip] = src_mac
            elif self.existing_arp_table[src_ip].upper() != src_mac:  # Check if MAC has changed
                self.new_entry.emit(src_ip, src_mac, 'Changed', self.existing_arp_table[src_ip])
                self.existing_arp_table[src_ip] = src_mac
            
    def stop_sniffing(self, pkt):
        return not self.running

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.local_arp_table = {}
        self.interface_mapping = self.create_interface_mapping()
        self.initUI()
        self.initialize_local_arp_table()  # Initialize the ARP table at startup


    def initUI(self):
        self.setWindowTitle("ARP Watcher")
        self.setGeometry(100, 100, 600, 400)
        layout = QVBoxLayout()

        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(4)  # Adjusted for status
        self.table_widget.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Status", "Old MAC Address"])

        self.interface_selector = QComboBox()
        # Add friendly names to the combo box
        for intf, name in self.interface_mapping.items():
            self.interface_selector.addItem(name, intf)

        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self.start_monitoring)

        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Interface:"))
        top_layout.addWidget(self.interface_selector)
        top_layout.addWidget(self.start_button)
        top_layout.addWidget(self.stop_button)

        layout.addWidget(self.table_widget)
        layout.addLayout(top_layout)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        self.sniffer = None

    def create_interface_mapping(self):
        """ Return a mapping of interface friendly names to Scapy-compatible names """
        winList = get_windows_if_list()
        intfList = get_if_list()
        mapping = {}

        # Extract GUID from intfList and use it to map names from winList
        for intf in intfList:
            guid = intf.split('_')[-1][1:-1]  # Extract the GUID part from the interface name
            for win in winList:
                if win['guid'] == '{' + guid + '}':  # Check if GUIDs match (note the addition of braces)
                    mapping[intf] = win['name']
                    break
        return mapping


    def initialize_local_arp_table(self):
        # Use arp -a command and parse its output to get the current ARP table entries
        try:
            arp_output = subprocess.check_output("arp -a", shell=True).decode()
            # The expected output format on Windows is 'IP address       HW type  HW address           Flags'
            for line in arp_output.split('\n'):
                # Using regex to match IP and MAC address patterns
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F-]{2}-[\da-fA-F-]{2}-[\da-fA-F-]{2}-[\da-fA-F-]{2}-[\da-fA-F-]{2}-[\da-fA-F-]{2})\s+(dynamic|static)', line)
                if match:
                    ip_address = match.group(1)
                    mac_address = match.group(2).replace('-', ':')
                    # Add to local ARP table and display it in the GUI
                    self.local_arp_table[ip_address] = mac_address
                    self.add_entry(ip_address, mac_address, 'Existing', None)
        except subprocess.CalledProcessError as e:
            print(f"Failed to read ARP table: {e}")



    @pyqtSlot()
    def start_monitoring(self):
        friendly_name = self.interface_selector.currentText()
        # Retrieve the Scapy-compatible name (interface identifier) for the selected friendly name
        scapy_intf = self.interface_selector.currentData()
        self.sniffer = ArpSniffer(scapy_intf)
        self.sniffer.new_entry.connect(self.add_entry)
        self.sniffer.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_bar.showMessage("Monitoring started on interface: " + friendly_name)

    @pyqtSlot()
    def stop_monitoring(self):
        if self.sniffer:
            self.sniffer.running = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("Monitoring stopped.")

    @pyqtSlot(str, str, str, str)
    def add_entry(self, ip, new_mac, status, old_mac):
        # Check if the entry already exists and update if there's a change
        for row in range(self.table_widget.rowCount()):
            if self.table_widget.item(row, 0).text() == ip:
                if status == 'Changed':  # Add a new row only if the MAC address has changed
                    self.table_widget.insertRow(row + 1)  # Insert a new row right below the existing one
                    self.table_widget.setItem(row + 1, 0, QTableWidgetItem(ip))
                    self.table_widget.setItem(row + 1, 1, QTableWidgetItem(new_mac))
                    self.table_widget.setItem(row + 1, 2, QTableWidgetItem(status))
                    self.table_widget.setItem(row + 1, 3, QTableWidgetItem(old_mac))
                return  # If IP exists, no further action is required

        # If IP doesn't exist, add it as a new entry
        row_count = self.table_widget.rowCount()
        self.table_widget.insertRow(row_count)
        self.table_widget.setItem(row_count, 0, QTableWidgetItem(ip))
        self.table_widget.setItem(row_count, 1, QTableWidgetItem(new_mac))
        self.table_widget.setItem(row_count, 2, QTableWidgetItem(status))
        self.table_widget.setItem(row_count, 3, QTableWidgetItem(old_mac))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
