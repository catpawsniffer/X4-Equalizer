#!/usr/bin/env python3

# A simple Python Program with Gui to Control the Equalizer of the X4 Soundblaster
# Copyright (C) 2026  Cat Sniffer catpawsniffer@proton.me

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Uses Qt-6 library https://www.qt.io/development/qt-framework/qt6
    
import serial
import time
import struct
import sys
import os

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtWidgets import QApplication, QMainWindow, QFrame, QLabel
from PySide6.QtCore import  QRect, Qt
from PySide6.QtGui import   QFont

import numpy as np
import pyqtgraph as pg

from scipy.interpolate import * #CubicSpline

import threading

import collections   #deque "ring buffer"

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serial.tools import list_ports

from ui_gui  import Ui_MainWindow



#################################################################################
# Static portion recovered from CTCDC.dll.
#
# The complete key is:
#
#   challenge[0:2]
#   + STATIC_KEY_MIDDLE
#   + challenge[2:4]
#
#  AES-256
#  GCM-Mode
#  16 Byte IV-Field (random numbers)
#  32 Byte Ciphertext
#  16 Byte Authentication Tag
#  GCM Nonce = first 12 Bytes of IV

CHALLENGE_PREFIX = b"whoareyou"   
UNLOCK_PREFIX = b"unlock"
CRLF = b"\r\n" 

STATIC_KEY_MIDDLE = bytes.fromhex(
        "d3 1a 21 27 9b e3 46 f0 99 9d 6e c4 c3 fe "
        "be 98 90 18 69 c1 18 fb b1 25 6e 0c e0 7b") #28 bytes
        
##########################################################        
        
preamp_prefix = bytes.fromhex("5a 12 07 01 96 0a")
prefix_1 =      bytes.fromhex("5a 12 07 01 96 0b")
prefix_2 =      bytes.fromhex("5a 12 07 01 96 0c")
prefix_3 =      bytes.fromhex("5a 12 07 01 96 0d")
prefix_4 =      bytes.fromhex("5a 12 07 01 96 0e")
prefix_5 =      bytes.fromhex("5a 12 07 01 96 0f")
prefix_6 =      bytes.fromhex("5a 12 07 01 96 10")
prefix_7 =      bytes.fromhex("5a 12 07 01 96 11")
prefix_8 =      bytes.fromhex("5a 12 07 01 96 12")
prefix_9 =      bytes.fromhex("5a 12 07 01 96 13")
prefix_10 =     bytes.fromhex("5a 12 07 01 96 14")

# float_p9 =  [00001041]
# float_m9 =  [0x00, 0x00, 0x10, 0xc1]
# float_p12 = [00004041]
# float_m12 = [000040c1]
# float_0 =   [ba54723b]

#request_preamp_value_sp =     bytes.fromhex("5a110301960a") #not sure
#request_preamp_value_hp =     bytes.fromhex("")       
#preamp_answer_prefix_sp =     bytes.fromhex("5a11080100960a")
#preamp_answer_prefix_hp =     bytes.fromhex("")

request_eq_1_data_speakers =  bytes.fromhex("5a170401020000") #r = 62+34
request_eq_2_data_speakers =  bytes.fromhex("5a170401020100") #r = 62+34
request_eq_3_data_speakers =  bytes.fromhex("5a170401020200") #r = 62+34
eq_1_data_speakers_prefix_1 = bytes.fromhex("5a173b010200004c")  #8bytes
eq_2_data_speakers_prefix_1 = bytes.fromhex("5a173b010201004c")
eq_3_data_speakers_prefix_1 = bytes.fromhex("5a173b010202004c")
eq_1_data_speakers_prefix_2 = bytes.fromhex("5a171f010200004c")
eq_2_data_speakers_prefix_2 = bytes.fromhex("5a171f010201004c")
eq_3_data_speakers_prefix_2 = bytes.fromhex("5a171f010202004c")

request_eq_1_data_headphones =  bytes.fromhex("5a170401020002") #r = 62 + 34 = 96   
request_eq_2_data_headphones =  bytes.fromhex("5a170401020102")
request_eq_3_data_headphones =  bytes.fromhex("5a170401020202")
eq_1_data_headphones_prefix_1 = bytes.fromhex("5a173b010200024c") #8bytes
eq_2_data_headphones_prefix_1 = bytes.fromhex("5a173b010201024c")
eq_3_data_headphones_prefix_1 = bytes.fromhex("5a173b010202024c")
eq_1_data_headphones_prefix_2 = bytes.fromhex("5a171f010200024c")
eq_2_data_headphones_prefix_2 = bytes.fromhex("5a171f010201024c")
eq_3_data_headphones_prefix_2 = bytes.fromhex("5a171f010202024c")

#new_prefix_1 =                  bytes.fromhex("5a173b010201024c")
#new_prefix_2 =                  bytes.fromhex("5a171f010201024c")
#preamp 5a11080100960a

select_eq_1 = bytes.fromhex("5a 1a 03 00 02 00") #response = 13 long
select_eq_2 = bytes.fromhex("5a 1a 03 00 02 01")
select_eq_3 = bytes.fromhex("5a 1a 03 00 02 02")
ack_eq_change =   bytes.fromhex("5a020a1a000000000000000000") #13

################

command_switch_to_headphones = bytes.fromhex("5a2c050004000000")   # host -> device 
command_switch_to_speakers   = bytes.fromhex("5a2c050001000000")   # host -> device
ack_sphp_change = bytes.fromhex("5a020a2c000000000000000000")  #13bytes

##################

eq_ack =   bytes.fromhex("5a020a12000000000000000000") #13

question_if_sp_or_hp =   bytes.fromhex("5a2c0101")
answer_speakers =        bytes.fromhex("5a2c050101000000")
answer_headphones =      bytes.fromhex("5a2c050104000000") #8
answer_sp_or_hp_prefix = bytes.fromhex("5a2c0501") #4
  
question_which_eq_is_active =  bytes.fromhex("5a1a03010200")
answer_eq_1_is_active =        bytes.fromhex("5a1a020200")
answer_eq_2_is_active =        bytes.fromhex("5a1a020201")
answer_eq_3_is_active =        bytes.fromhex("5a1a020202")   #5
answer_eq_x_is_active_prefix = bytes.fromhex("5a1a0202") #4
    
question_eq_on_off =     bytes.fromhex("5a1103019609")
answer_eq_off =          bytes.fromhex("5a11080100960900000000") #11
answer_eq_on =           bytes.fromhex("5a1108010096090000803f")
answer_eq_onoff_prefix = bytes.fromhex("5a1108010096090000") #9
    
eq_off_command = bytes.fromhex("5a120701960900000000")
eq_on_command =  bytes.fromhex("5a12070196090000803f")
#eq_on_ack =      bytes.fromhex("")
#eq_off_ack =     bytes.fromhex("")

swmode1 = bytes.fromhex("53575f4d4f4445310d0a")
start = bytes.fromhex("5a0300") #my guess


##################### X4 Serial Port Detect

#idVendor   0x041e Creative Technology, Ltd
#idProduct  0x3278 Sound Blaster X4

VID = 0x041e
PID = 0x3278

port = None
ser = None    
    
def open_serial_port():
    
    global port
    global ser
    
    device_list = list_ports.comports()
    for device in device_list:
        #print(device)
        if (device.vid == VID and device.pid == PID):
            port = device.device
            break
    if port == None:
        print("X4 not found or serial port not accessible")

    if port != None:            
        print("X4 found at ", port)


    ser = serial.Serial(port, timeout=2)
    
    
    # ##################### OS Detect

    # if sys.platform == "linux": 
        # print("linux detected")
        # #ser = serial.Serial('/dev/ttyACM0', timeout=0.5)#, write_timeout=0.5)
        # ser = serial.Serial(port, timeout=1)#
        
        
    # elif sys.platform == "win32":  
        # print("windows detected")
        # #ser = serial.Serial('COM3', timeout=0.5)#, write_timeout=0.5)  
        # ser = serial.Serial(port, timeout=1)
  
  

#######################################


######################################

def generate_response_packet(challenge_packet_: bytes) -> bytes:

    c_prefix = challenge_packet_[0:9]     #b"whoareyou"
    c_header = challenge_packet_[9:13]    #4 byte
    challenge = challenge_packet_[13:45]  #32 byte  


    key = c_header[0:2] + STATIC_KEY_MIDDLE + c_header[2:4]


    print(str(c_prefix))
    print(c_header.hex(" ")) 
    print("challenge ", challenge.hex(" "))
    print("len challenge ", len(challenge))
    print("key ", key.hex(" "))
    print("len key ", len(key))


    # Convert the 32-byte X4 challenge nonce into:
    # "unlock" + IV(16) + ciphertext(32) + tag(16) + CRLF

    # AES-256-GCM nonce = IV[0:12]

    # # Creative uses a 16-byte IV, with the first 12 bytes becoming
    # # the actual GCM nonce.

    iv = os.urandom(16)
    gcm_nonce = iv[:12]

    aes = AESGCM(key)

    encrypted = aes.encrypt(
         gcm_nonce,
         challenge,
         None,
    )

    # cryptography's AESGCM.encrypt() returns:
    #
    #   ciphertext || 16-byte authentication tag
    #

    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    assert len(ciphertext) == 32
    assert len(tag) == 16

    return (            #full response packet
        UNLOCK_PREFIX   #"unlock"
        + iv            #16 byte
        + ciphertext    #32 byte
        + tag           #16 byte
        + CRLF          #CRLF = b"\r\n" 
    )

#########################################
    
def unlock_device():

    # Start with a clean input buffer.
    ser.reset_input_buffer()
    
    #swmode1 =  [0x53, 0x57, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x31, 0xd, 0xa]
    #swmode1 = bytes.fromhex("53 57 5f 4d 4f 44 45 31 0d 0a")
    #start = bytes.fromhex("5a 03 00")
    #start = [0x5a, 0x03, 0x00]
    #whoareyoumyapp = bytes.fromhex("77686f617265796f752e4d79417070380d0a")
    
    unknown_command = bytes.fromhex("55 6e 6b 6e 6f 77 6e 20 63 6f 6d 6d 61 6e 64 0d 0a")
    allgood = bytes.fromhex("5a 03 02 3b 00")  #??
    greeting = b"whoareyou.MyApp8\r\n"
    
    print(f"[>] {start.hex()!r}")
    ser.write(start)
    ser.flush()
        
    print(f"[>] {greeting!r}")
    ser.write(greeting)
    ser.flush()
    print(f"[>] {greeting!r}")
    ser.write(greeting)
    ser.flush()
    
    challenge_packet = read_until_idle(ser)
    
    if challenge_packet == unknown_command:
        print("unknown command")
        
    if challenge_packet[0:9] == CHALLENGE_PREFIX:
        
        print("challenge detected ###############################")
        
        response_packet = generate_response_packet(challenge_packet)
    
        print("response: ", response_packet.hex(" "))

        ser.write(response_packet)
        ser.flush()

        result = read_until_idle(
            ser,
            idle_time=0.2,
            overall_timeout=3.0,
        )

        print("[<]", result)

        if b"unlock_OK" in result:
            print("[+] X4 authentication successful ######################")
        else:
            print("[!] No unlock_OK received")
    
    if challenge_packet == allgood:
        print(f"[<] allgood")
        #print("allgood")
        time.sleep(0.5)
        print(f"[>] {start.hex()!r}")
        ser.write(start)

    if challenge_packet != allgood:
        
        ser.write(swmode1)
        time.sleep(0.5)
        print(f"[>] {start.hex()!r}")
        ser.write(start)
   
###################################################################    
    

def read_until_idle(ser, idle_time=0.25, overall_timeout=1):  
    
    #Read serial data until no new data has arrived for idle_time,
    #or overall_timeout has elapsed.

    data = bytearray()
    start = time.monotonic()
    last_data = start

    while True:
        now = time.monotonic()

        if now - start > overall_timeout:
            break

        chunk = ser.read(4069)

        if chunk:
            data.extend(chunk)
            last_data = time.monotonic()
        elif data and time.monotonic() - last_data >= idle_time:
            break
 
    return bytes(data)    
    

####################################################################


class MainWindow(QMainWindow):
 
    value_float = [0]*11   #value of the sliders
    timeout_counter = 0
 
 
    def __init__(self):
        super(MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
        self.ui.verticalSlider_preamp.valueChanged.connect(self.preamp_slider)
        self.ui.verticalSlider_1.valueChanged.connect(self._1_slider)
        self.ui.verticalSlider_2.valueChanged.connect(self._2_slider)
        self.ui.verticalSlider_3.valueChanged.connect(self._3_slider)
        self.ui.verticalSlider_4.valueChanged.connect(self._4_slider)
        self.ui.verticalSlider_5.valueChanged.connect(self._5_slider)
        self.ui.verticalSlider_6.valueChanged.connect(self._6_slider)
        self.ui.verticalSlider_7.valueChanged.connect(self._7_slider)
        self.ui.verticalSlider_8.valueChanged.connect(self._8_slider)
        self.ui.verticalSlider_9.valueChanged.connect(self._9_slider)
        self.ui.verticalSlider_10.valueChanged.connect(self._10_slider)
        
        
        self.ui.verticalSlider_1.label = QLabel(self)  #i dont know if this is the right way but it works for me somehow....
        self.ui.verticalSlider_2.label = QLabel(self)
        self.ui.verticalSlider_3.label = QLabel(self)
        self.ui.verticalSlider_4.label = QLabel(self)
        self.ui.verticalSlider_5.label = QLabel(self)
        self.ui.verticalSlider_6.label = QLabel(self)
        self.ui.verticalSlider_7.label = QLabel(self)
        self.ui.verticalSlider_8.label = QLabel(self)
        self.ui.verticalSlider_9.label = QLabel(self)
        self.ui.verticalSlider_10.label = QLabel(self)
        self.ui.verticalSlider_preamp.label = QLabel(self)
        
        self.ui.verticalSlider_1.setup()
        self.ui.verticalSlider_2.setup()
        self.ui.verticalSlider_3.setup()
        self.ui.verticalSlider_4.setup()
        self.ui.verticalSlider_5.setup()
        self.ui.verticalSlider_6.setup()
        self.ui.verticalSlider_7.setup()
        self.ui.verticalSlider_8.setup()
        self.ui.verticalSlider_9.setup()
        self.ui.verticalSlider_10.setup()
        self.ui.verticalSlider_preamp.length = 70
        self.ui.verticalSlider_preamp.setup()
        self.ui.verticalSlider_preamp.offset = 110          
        self.ui.verticalSlider_preamp.factor = 1.0
        self.ui.verticalSlider_preamp.label.setAlignment(Qt.AlignmentFlag.AlignCenter)

             
        self.ui.comboBox_eqonoff.currentIndexChanged.connect(self.comboBox_eqonoff_changed)
        self.ui.comboBox_sphp.currentIndexChanged.connect(self.comboBox_sphp_changed)
        self.ui.comboBox_eq.currentIndexChanged.connect(self.comboBox_eq_changed)
    
        self.ui.EqView.showGrid(x=False, y=False, alpha=0.3)
        self.ui.EqView.hideAxis('left') 
        self.ui.EqView.hideAxis('bottom') 
        self.ui.EqView.disableAutoRange()
        self.ui.EqView.setMouseEnabled(False, False)
        self.ui.EqView.setXRange(-0.1, 8.8)
        self.ui.EqView.setYRange(-9.7, 9.7)
        self.ui.EqView.setBackground('w')
        self.ui.EqView.hideButtons()


        self.plot_view()
        
        
    def check_ack(self):

        #ack_reply = ser.read_until(eq_ack)
        #if ack_reply[-len(eq_ack):] == eq_ack:
        #    print ("eq ack")
        #print("ack") 
        dummy = 0
        
     
    def comboBox_eqonoff_changed(self):
        #print("comboBox_eqonoff")
        #dummy = read_until_idle(ser)
        #time.sleep(1)
        button_thread.active = 0
        while (button_thread.ready == 0):
            time.sleep(0.01)
        time.sleep(0.1)
        # time.sleep(1)
        #dummy = read_until_idle(ser)
        
        if self.ui.comboBox_eqonoff.currentText() == "Equalizer On":
            #print("Equalizer On")
            #self.ui.comboBox_sphp.setEnabled(1)
            self.ui.comboBox_eq.setEnabled(1)
            
            ser.write(eq_on_command)
            answer = ser.read_until(answer_eq_on)
            answer = ser.read_until(eq_ack)

            self.ui.verticalSlider_1.setEnabled(1)
            self.ui.verticalSlider_2.setEnabled(1)
            self.ui.verticalSlider_3.setEnabled(1)
            self.ui.verticalSlider_4.setEnabled(1)
            self.ui.verticalSlider_5.setEnabled(1)
            self.ui.verticalSlider_6.setEnabled(1)
            self.ui.verticalSlider_7.setEnabled(1)
            self.ui.verticalSlider_8.setEnabled(1)
            self.ui.verticalSlider_9.setEnabled(1)
            self.ui.verticalSlider_10.setEnabled(1)
            self.ui.verticalSlider_preamp.setEnabled(1)
            
            #print("init gui")
            self.initialize_gui()
     
        if self.ui.comboBox_eqonoff.currentText() == "Equalizer Off":
            print("Equalizer Off")
            #self.ui.comboBox_sphp.setEnabled(0)
            self.ui.comboBox_eq.setEnabled(0)
            ser.write(eq_off_command)
            #dummy = read_until_idle(ser)

            self.slider_connect_disconnect()
            self.ui.verticalSlider_1.setEnabled(0)
            self.ui.verticalSlider_1.setValue(0)
            self.ui.verticalSlider_2.setEnabled(0)
            self.ui.verticalSlider_2.setValue(0)
            self.ui.verticalSlider_3.setEnabled(0)
            self.ui.verticalSlider_3.setValue(0)
            self.ui.verticalSlider_4.setEnabled(0)
            self.ui.verticalSlider_4.setValue(0)
            self.ui.verticalSlider_5.setEnabled(0)
            self.ui.verticalSlider_5.setValue(0)
            self.ui.verticalSlider_6.setEnabled(0)
            self.ui.verticalSlider_6.setValue(0)
            self.ui.verticalSlider_7.setEnabled(0)
            self.ui.verticalSlider_7.setValue(0)
            self.ui.verticalSlider_8.setEnabled(0)
            self.ui.verticalSlider_8.setValue(0)
            self.ui.verticalSlider_9.setEnabled(0)
            self.ui.verticalSlider_9.setValue(0)
            self.ui.verticalSlider_10.setEnabled(0)
            self.ui.verticalSlider_10.setValue(0)
            self.ui.verticalSlider_preamp.setEnabled(0)
            self.ui.verticalSlider_preamp.setValue(0)
            self.slider_connect_connect()
            for i in range(0, 11):
                self.value_float[i] = float(0)
            
            #print([ '%.1f' % elem for elem in self.value_float ]) #round list to x.x
            self.plot_view()
            
            self.ui.verticalSlider_1.label.setHidden(1)
            self.ui.verticalSlider_2.label.setHidden(1)
            self.ui.verticalSlider_3.label.setHidden(1)
            self.ui.verticalSlider_4.label.setHidden(1)
            self.ui.verticalSlider_5.label.setHidden(1)
            self.ui.verticalSlider_6.label.setHidden(1)
            self.ui.verticalSlider_7.label.setHidden(1)
            self.ui.verticalSlider_8.label.setHidden(1)
            self.ui.verticalSlider_9.label.setHidden(1)
            self.ui.verticalSlider_10.label.setHidden(1)
            self.ui.verticalSlider_preamp.label.setHidden(1)
            
            
        #ser.flush() 
        time.sleep(0.5)
        #dummy = read_until_idle(ser)
        button_thread.active = 1
            
    def comboBox_sphp_changed(self):     
        #dummy = read_until_idle(ser)
        #time.sleep(1)
        
        self.ui.comboBox_eqonoff.setEnabled(0)
        self.ui.comboBox_eq.setEnabled(0)
        
        button_thread.active = 0
        while (button_thread.ready == 0):
            time.sleep(0.01)
        time.sleep(0.1)
        
        #time.sleep(1)
        #dummy = read_until_idle(ser)
        #print("comboBox_sphp")
        ####dummy = read_until_idle(ser)
        
        #if self.ui.comboBox_eqonoff.currentIndex() == 0: #if eq on
        
        if self.ui.comboBox_sphp.currentText() == "Speakers":
            print("Speakers selected")
            #dummy = read_until_idle(ser)
            ser.write(command_switch_to_speakers)  
            answer = ser.read_until(ack_sphp_change)                   #ack_sphp
            #if answer[-13:] == ack_sphp_change:
            #    print ("ack_sphp_change")
            #read_and_parse_values__little()
            #dummy = read_until_idle(ser)   ####  
            #print("sphp_switch ack ", answer.hex())
            
            if self.ui.comboBox_eqonoff.currentIndex() == 0:     #if eq is on
            
            
                ser.write(question_which_eq_is_active)
                #answer = ser.read(5)
                answer = ser.read_until(answer_eq_x_is_active_prefix) #4
                answer = answer_eq_x_is_active_prefix + ser.read(1)
                
                if answer == answer_eq_1_is_active:
                    print("Equalizer 1")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_1_data_speakers)
                    self.read_and_parse_values(request_eq_1_data_speakers, eq_1_data_speakers_prefix_1, eq_1_data_speakers_prefix_2)
                    #dummy = read_until_idle(ser)
                    
                if answer == answer_eq_2_is_active:
                    print("Equalizer 2")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_2_data_speakers)
                    self.read_and_parse_values(request_eq_2_data_speakers, eq_2_data_speakers_prefix_1, eq_2_data_speakers_prefix_2)
                    #dummy = read_until_idle(ser)
                
                if answer == answer_eq_3_is_active:
                    print("Equalizer 3")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_3_data_speakers)
                    self.read_and_parse_values(request_eq_3_data_speakers, eq_3_data_speakers_prefix_1, eq_3_data_speakers_prefix_2)
                    #dummy = read_until_idle(ser)
                
     
        if self.ui.comboBox_sphp.currentText() == "Headphones":
            print("Headphones selected")
            #dummy = read_until_idle(ser)
            ser.write(command_switch_to_headphones)  
            answer = ser.read_until(ack_sphp_change)                   #ack_sphp
            #if answer[-13:] == ack_sphp_change:
            #    print ("ack_sphp_change")
            #print("sphp_switch ack ", answer.hex())
            
            #read_and_parse_values__little()
            #dummy = read_until_idle(ser)    
            
            
            if self.ui.comboBox_eqonoff.currentIndex() == 0:  #if eq is on
            
                ser.write(question_which_eq_is_active)
                #answer = ser.read(5)
                answer = ser.read_until(answer_eq_x_is_active_prefix) #4
                answer = answer_eq_x_is_active_prefix + ser.read(1)
                
                if answer == answer_eq_1_is_active:
                    print("Equalizer 1")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_1_data_headphones)
                    self.read_and_parse_values(request_eq_1_data_headphones, eq_1_data_headphones_prefix_1, eq_1_data_headphones_prefix_2)
                    #dummy = read_until_idle(ser)
             
                if answer == answer_eq_2_is_active:
                    print("Equalizer 2")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_2_data_headphones)
                    self.read_and_parse_values(request_eq_2_data_headphones, eq_2_data_headphones_prefix_1, eq_2_data_headphones_prefix_2)
                    #dummy = read_until_idle(ser)
     
                if answer == answer_eq_3_is_active:
                    print("Equalizer 3")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_3_data_headphones)
                    self.read_and_parse_values(request_eq_3_data_headphones, eq_3_data_headphones_prefix_1, eq_3_data_headphones_prefix_2)
                    #dummy = read_until_idle(ser)
        
        #ser.flush()
        time.sleep(0.5)
        #dummy = read_until_idle(ser)
        button_thread.active = 1
        
        self.ui.comboBox_sphp.setEnabled(1)
        
        if self.ui.comboBox_eqonoff.currentIndex() == 0:  #if eq is on
        #if self.ui.comboBox_eqonoff.currentText() == "Equalizer On":
            self.ui.comboBox_eq.setEnabled(1)
            self.ui.comboBox_eqonoff.setEnabled(1)
            
        if self.ui.comboBox_eqonoff.currentIndex() == 1:  #if eq is off
        #if self.ui.comboBox_eqonoff.currentText() == "Equalizer Off":
            self.ui.comboBox_eq.setEnabled(0)
            self.ui.comboBox_eqonoff.setEnabled(1)
            
             
    def comboBox_eq_changed(self):
        #print("combobox_eq")
        #time.sleep(1)
        #dummy = read_until_idle(ser)
        
        self.ui.comboBox_sphp.setEnabled(0)
        self.ui.comboBox_eqonoff.setEnabled(0)
        
        button_thread.active = 0
        #dummy = read_until_idle(ser)
        while (button_thread.ready == 0):
            time.sleep(0.01)
        time.sleep(0.1)
        #time.sleep(1)
        #dummy = read_until_idle(ser)
        
        if self.ui.comboBox_eqonoff.currentIndex() == 0: #if eq on
                
            
            if self.ui.comboBox_eq.currentText() == "Equalizer 1":
                print("Equalizer 1")
                #dummy = read_until_idle(ser)
                ser.write(question_if_sp_or_hp)
                #answer_sp_or_hp = ser.read(8)
                
                answer_sp_or_hp = ser.read_until(answer_sp_or_hp_prefix) #4
                answer_sp_or_hp = answer_sp_or_hp_prefix + ser.read(4)
                
                
                self.ui.comboBox_eq.setCurrentIndex(0)
                
                if answer_sp_or_hp == answer_speakers:
                    print("Speakers selected")
                    self.ui.comboBox_sphp.setCurrentIndex(0)
                    ser.write(select_eq_1)
                    #answer = ser.read(13)
                    answer = ser.read_until(ack_eq_change)
                    #if answer[-13:] == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_1_data_speakers)
                    self.read_and_parse_values(request_eq_1_data_speakers, eq_1_data_speakers_prefix_1, eq_1_data_speakers_prefix_2)
                    #dummy = read_until_idle(ser)
                    
                if answer_sp_or_hp == answer_headphones:
                    print("Headphones selected")
                    self.ui.comboBox_sphp.setCurrentIndex(1)
                    ser.write(select_eq_1)
                    #answer = ser.read(13)
                    answer = ser.read_until(ack_eq_change)
                    #if answer[-13:] == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_1_data_headphones)  
                    self.read_and_parse_values(request_eq_1_data_headphones, eq_1_data_headphones_prefix_1, eq_1_data_headphones_prefix_2)
                    #dummy = read_until_idle(ser)
         
            if self.ui.comboBox_eq.currentText() == "Equalizer 2":
                print("Equalizer 2")
                #dummy = read_until_idle(ser)
                ser.write(question_if_sp_or_hp)
                #answer_sp_or_hp = ser.read(8)
                
                answer_sp_or_hp = ser.read_until(answer_sp_or_hp_prefix) #4
                answer_sp_or_hp = answer_sp_or_hp_prefix + ser.read(4)
                
                self.ui.comboBox_eq.setCurrentIndex(1)
                
                if answer_sp_or_hp == answer_speakers:
                    print("Speakers selected")
                    self.ui.comboBox_sphp.setCurrentIndex(0)
                    ser.write(select_eq_2)
                    #answer = ser.read(13)
                    answer = ser.read_until(ack_eq_change)
                    #if answer[-13:] == ack_eq_change:
                    #    print ("ack_eq_change")  
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_2_data_speakers)
                    self.read_and_parse_values(request_eq_2_data_speakers, eq_2_data_speakers_prefix_1, eq_2_data_speakers_prefix_2)
                    #dummy = read_until_idle(ser)
                    
                if answer_sp_or_hp == answer_headphones:
                    print("Headphones selected")
                    self.ui.comboBox_sphp.setCurrentIndex(1)
                    ser.write(select_eq_2)
                    #answer = ser.read(13)
                    answer = ser.read_until(ack_eq_change)
                    #if answer[-13:] == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_2_data_headphones) 
                    self.read_and_parse_values(request_eq_2_data_headphones, eq_2_data_headphones_prefix_1, eq_2_data_headphones_prefix_2)
                    #dummy = read_until_idle(ser)
                
                
            if self.ui.comboBox_eq.currentText() == "Equalizer 3":
                print("Equalizer 3")
                #dummy = read_until_idle(ser)
                ser.write(question_if_sp_or_hp)
                #answer_sp_or_hp = ser.read(8)
                answer_sp_or_hp = ser.read_until(answer_sp_or_hp_prefix) #4
                answer_sp_or_hp = answer_sp_or_hp_prefix + ser.read(4)
                
                self.ui.comboBox_eq.setCurrentIndex(2)
                
                if answer_sp_or_hp == answer_speakers:
                    print("Speakers selected")
                    self.ui.comboBox_sphp.setCurrentIndex(0)
                    ser.write(select_eq_3)
                    #dummy = read_until_idle(ser)
                    #answer = ser.read(13)
                    answer = ser.read_until(ack_eq_change)
                    #if answer[-13:] == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_3_data_speakers)
                    self.read_and_parse_values(request_eq_3_data_speakers, eq_3_data_speakers_prefix_1, eq_3_data_speakers_prefix_2)
                    #dummy = read_until_idle(ser)
                    
                if answer_sp_or_hp == answer_headphones:
                    print("Headphones selected")
                    self.ui.comboBox_sphp.setCurrentIndex(1)
                    ser.write(select_eq_3)
                    #dummy = read_until_idle(ser)
                    #answer = ser.read(13)
                    answer = ser.read_until(ack_eq_change)
                    #if answer[-13:] == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_3_data_headphones) 
                    self.read_and_parse_values(request_eq_3_data_headphones, eq_3_data_headphones_prefix_1, eq_3_data_headphones_prefix_2)
                    #dummy = read_until_idle(ser)
                    
            #dummy = read_until_idle(ser)  
        
        #ser.flush()
        time.sleep(0.5)
        #dummy = read_until_idle(ser)
        button_thread.active = 1
        self.ui.comboBox_sphp.setEnabled(1)
        self.ui.comboBox_eqonoff.setEnabled(1)
        
    def plot_view(self):
    
        x = np.arange(10)

        y = self.value_float[0:10]

        #spline = CubicSpline(x, y)
        #spline = make_interp_spline(x, y, 2)
        spline = PchipInterpolator(x, y) #good!
        #spline = Akima1DInterpolator(x, y)
        #spline = BarycentricInterpolator(x, y)
        #spline = KroghInterpolator(x, y)

        x_smooth = np.linspace(x[0], x[-1], 500)
        y_smooth = spline(x_smooth)

        
        self.ui.EqView.clear()
        self.ui.EqView.plot(
            x_smooth,
            y_smooth,
            pen=pg.mkPen(color=(20, 100, 13), width=5)
        )

        self.ui.EqView.plot(
            x,
            y,
            pen=None,
            symbol="o",
            symbolSize=10,
            symbolBrush="w",
            symbolPen=pg.mkPen(width=2)
        )
        
        
    def _1_slider(self):
    
        value = float(self.ui.verticalSlider_1.value())/10
        self.value_float[0] = value
        ser.write(prefix_1 + struct.pack("<f", value))
        ser.flush()
        #print(value)
        #self.ui.verticalSlider_1.setStatusTip(str(value))
        #self.ui.verticalSlider_1.setToolTip(str(value))
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _2_slider(self):
    
        value = float(self.ui.verticalSlider_2.value())/10
        self.value_float[1] = value
        ser.write(prefix_2 + struct.pack("<f", value))   
        ser.flush()
        #print(value)
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _3_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_3.value())/10
        self.value_float[2] = value
        ser.write(prefix_3 + struct.pack("<f", value))   
        ser.flush()
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _4_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_4.value())/10
        self.value_float[3] = value
        ser.write(prefix_4 + struct.pack("<f", value))
        ser.flush()
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _5_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_5.value())/10
        self.value_float[4] = value
        ser.write(prefix_5 + struct.pack("<f", value)) 
        ser.flush()
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _6_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_6.value())/10
        self.value_float[5] = value
        ser.write(prefix_6 + struct.pack("<f", value)) 
        ser.flush()
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _7_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_7.value())/10
        self.value_float[6] = value
        ser.write(prefix_7 + struct.pack("<f", value))   
        ser.flush()
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _8_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_8.value())/10
        self.value_float[7] = value
        ser.write(prefix_8 + struct.pack("<f", value))  
        ser.flush()
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _9_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_9.value())/10
        self.value_float[8] = value
        ser.write(prefix_9 + struct.pack("<f", value))  
        ser.flush()
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def _10_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_10.value())/10
        self.value_float[9] = value
        ser.write(prefix_10 + struct.pack("<f", value))  
        ser.flush()
        #ser.read(13)
        #self.check_ack()
        self.plot_view()
        
    def preamp_slider(self):
    
        #print("slide")
        value = float(self.ui.verticalSlider_preamp.value())/10
        ser.write(preamp_prefix + struct.pack("<f", value))
        ser.flush()
        #print(value)
        #ser.read(13)
        #self.check_ack()

    def initialize_gui(self):
        
        #time.sleep(1)
        button_thread.active = 0
        while (button_thread.ready == 0):
                time.sleep(0.01)
        time.sleep(0.1)
        #time.sleep(1)
        #dummy = read_until_idle(ser)
        #dummy = read_until_idle(ser)
        
        self.ui.comboBox_eqonoff.currentIndexChanged.disconnect(self.comboBox_eqonoff_changed)
        self.ui.comboBox_sphp.currentIndexChanged.disconnect(self.comboBox_sphp_changed)
        self.ui.comboBox_eq.currentIndexChanged.disconnect(self.comboBox_eq_changed)

        #EQ ON OFF ?
        #dummy = read_until_idle(ser)
        
        ser.write(question_eq_on_off)
        answer = ser.read_until(answer_eq_onoff_prefix)
        #if answer[-len(answer_eq_onoff_prefix):] == answer_eq_onoff_prefix:
        #    print("answer_eq_onoff_prefix found")
        answer = ser.read(2)
        answer = answer_eq_onoff_prefix + answer

        if answer == answer_eq_off:
            print("Equalizer Off")
            self.ui.comboBox_eqonoff.setCurrentIndex(1)
            #self.ui.comboBox_sphp.setEnabled(1)
            self.ui.comboBox_eq.setEnabled(0)
            
            self.slider_connect_disconnect()
            self.ui.verticalSlider_1.setEnabled(0)
            self.ui.verticalSlider_1.setValue(0)
            self.ui.verticalSlider_2.setEnabled(0)
            self.ui.verticalSlider_2.setValue(0)
            self.ui.verticalSlider_3.setEnabled(0)
            self.ui.verticalSlider_3.setValue(0)
            self.ui.verticalSlider_4.setEnabled(0)
            self.ui.verticalSlider_4.setValue(0)
            self.ui.verticalSlider_5.setEnabled(0)
            self.ui.verticalSlider_5.setValue(0)
            self.ui.verticalSlider_6.setEnabled(0)
            self.ui.verticalSlider_6.setValue(0)
            self.ui.verticalSlider_7.setEnabled(0)
            self.ui.verticalSlider_7.setValue(0)
            self.ui.verticalSlider_8.setEnabled(0)
            self.ui.verticalSlider_8.setValue(0)
            self.ui.verticalSlider_9.setEnabled(0)
            self.ui.verticalSlider_9.setValue(0)
            self.ui.verticalSlider_10.setEnabled(0)
            self.ui.verticalSlider_10.setValue(0)
            self.ui.verticalSlider_preamp.setEnabled(0)
            self.ui.verticalSlider_preamp.setValue(0)
            self.slider_connect_connect()
            
            ser.write(question_if_sp_or_hp)    
            answer_sp_or_hp = ser.read_until(answer_sp_or_hp_prefix) #4
            answer_sp_or_hp = answer_sp_or_hp_prefix + ser.read(4)
            
            if answer_sp_or_hp == answer_speakers:
                print("Speakers selected")
                self.ui.comboBox_sphp.setCurrentIndex(0)
            if answer_sp_or_hp == answer_headphones:
                print("Headphones selected")
                self.ui.comboBox_sphp.setCurrentIndex(1)
            
            
            
        if answer == answer_eq_on:
            print("Equalizer On")
            self.ui.comboBox_eqonoff.setCurrentIndex(0)
            #dummy = read_until_idle(ser)
            
            ser.write(question_which_eq_is_active)
            answer = ser.read_until(answer_eq_x_is_active_prefix)
            #if answer[-len(answer_eq_x_is_active_prefix):] == answer_eq_x_is_active_prefix:
            #    print("answer_eq_x_is_active_prefix")
            answer = ser.read(5)
            answer = answer_eq_x_is_active_prefix + answer
            
            if answer == answer_eq_1_is_active:
                print("Equalizer 1")
                #dummy = read_until_idle(ser)
                
                #ser.write(select_eq_1)
                #answer = ser.read_until(ack_eq_change)
                #if answer == ack_eq_change:
                #    print ("ack_eq_change")
                    
                ser.write(question_if_sp_or_hp)    
                answer_sp_or_hp = ser.read_until(answer_sp_or_hp_prefix) #4
                answer_sp_or_hp = answer_sp_or_hp_prefix + ser.read(4)
                
                self.ui.comboBox_eq.setCurrentIndex(0)
                
                if answer_sp_or_hp == answer_speakers:
                    print("Speakers selected")
                    self.ui.comboBox_sphp.setCurrentIndex(0)
                    #ser.write(select_eq_1)
                    #answer = ser.read_until(ack_eq_change)
                    #if answer == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_1_data_speakers)
                    self.read_and_parse_values(request_eq_1_data_speakers, eq_1_data_speakers_prefix_1, eq_1_data_speakers_prefix_2)
                    
                if answer_sp_or_hp == answer_headphones:
                    print("Headphones selected")
                    self.ui.comboBox_sphp.setCurrentIndex(1)
                    #ser.write(select_eq_1)
                    #answer = ser.read_until(ack_eq_change)
                    #if answer == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_1_data_headphones)  
                    self.read_and_parse_values(request_eq_1_data_headphones, eq_1_data_headphones_prefix_1, eq_1_data_headphones_prefix_2)
                
            if answer == answer_eq_2_is_active:
                print("Equalizer 2")
                #dummy = read_until_idle(ser)
                
                #ser.write(select_eq_2)
                #answer = ser.read_until(ack_eq_change)
                #if answer == ack_eq_change:
                #    print ("ack_eq_change")


                ser.write(question_if_sp_or_hp)
                answer_sp_or_hp = ser.read_until(answer_sp_or_hp_prefix) #4
                answer_sp_or_hp = answer_sp_or_hp_prefix + ser.read(4)
                
                self.ui.comboBox_eq.setCurrentIndex(1)
                
                if answer_sp_or_hp == answer_speakers:
                    print("Speakers selected")
                    self.ui.comboBox_sphp.setCurrentIndex(0)
                    #ser.write(select_eq_2)
                    #answer = ser.read_until(ack_eq_change)
                    #if answer == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_2_data_speakers)
                    self.read_and_parse_values(request_eq_2_data_speakers, eq_2_data_speakers_prefix_1, eq_2_data_speakers_prefix_2)
                    
                if answer_sp_or_hp == answer_headphones:
                    print("Headphones selected")
                    self.ui.comboBox_sphp.setCurrentIndex(1)
                    #ser.write(select_eq_2)
                    #answer = ser.read_until(ack_eq_change)
                    #if answer == ack_eq_change:
                    #   print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_2_data_headphones) 
                    self.read_and_parse_values(request_eq_2_data_headphones, eq_2_data_headphones_prefix_1, eq_2_data_headphones_prefix_2)
            
            if answer == answer_eq_3_is_active:
                print("Equalizer 3")
                #dummy = read_until_idle(ser)
                
                #ser.write(select_eq_3)
                #answer = ser.read_until(ack_eq_change)
                #if answer == ack_eq_change:
                #    print ("ack_eq_change")
                    
                ser.write(question_if_sp_or_hp)
                answer_sp_or_hp = ser.read_until(answer_sp_or_hp_prefix) #4
                answer_sp_or_hp = answer_sp_or_hp_prefix + ser.read(4)
                
                self.ui.comboBox_eq.setCurrentIndex(2)
                
                if answer_sp_or_hp == answer_speakers:
                    print("Speakers selected")
                    self.ui.comboBox_sphp.setCurrentIndex(0)
                    #ser.write(select_eq_3)
                    #answer = ser.read_until(ack_eq_change)
                    #if answer == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_3_data_speakers)
                    self.read_and_parse_values(request_eq_3_data_speakers, eq_3_data_speakers_prefix_1, eq_3_data_speakers_prefix_2)
                    
                if answer_sp_or_hp == answer_headphones:
                    print("Headphones selected")
                    self.ui.comboBox_sphp.setCurrentIndex(1)
                    #ser.write(select_eq_3)
                    #answer = ser.read_until(ack_eq_change)
                    #if answer == ack_eq_change:
                    #    print ("ack_eq_change")
                    #dummy = read_until_idle(ser)
                    #ser.write(request_eq_3_data_headphones) 
                    self.read_and_parse_values(request_eq_3_data_headphones, eq_3_data_headphones_prefix_1, eq_3_data_headphones_prefix_2)
        
        self.ui.comboBox_eqonoff.currentIndexChanged.connect(self.comboBox_eqonoff_changed)
        self.ui.comboBox_sphp.currentIndexChanged.connect(self.comboBox_sphp_changed)
        self.ui.comboBox_eq.currentIndexChanged.connect(self.comboBox_eq_changed)
        
        
        time.sleep(0.2)
        #dummy = read_until_idle(ser)
        button_thread.active = 1
    
    def slider_connect_disconnect(self):


        self.ui.verticalSlider_preamp.valueChanged.disconnect(self.preamp_slider)
        self.ui.verticalSlider_1.valueChanged.disconnect(self._1_slider)
        self.ui.verticalSlider_2.valueChanged.disconnect(self._2_slider)
        self.ui.verticalSlider_3.valueChanged.disconnect(self._3_slider)
        self.ui.verticalSlider_4.valueChanged.disconnect(self._4_slider)
        self.ui.verticalSlider_5.valueChanged.disconnect(self._5_slider)
        self.ui.verticalSlider_6.valueChanged.disconnect(self._6_slider)
        self.ui.verticalSlider_7.valueChanged.disconnect(self._7_slider)
        self.ui.verticalSlider_8.valueChanged.disconnect(self._8_slider)
        self.ui.verticalSlider_9.valueChanged.disconnect(self._9_slider)
        self.ui.verticalSlider_10.valueChanged.disconnect(self._10_slider)

    def slider_connect_connect(self):

        self.ui.verticalSlider_preamp.valueChanged.connect(self.preamp_slider)
        self.ui.verticalSlider_1.valueChanged.connect(self._1_slider)
        self.ui.verticalSlider_2.valueChanged.connect(self._2_slider)
        self.ui.verticalSlider_3.valueChanged.connect(self._3_slider)
        self.ui.verticalSlider_4.valueChanged.connect(self._4_slider)
        self.ui.verticalSlider_5.valueChanged.connect(self._5_slider)
        self.ui.verticalSlider_6.valueChanged.connect(self._6_slider)
        self.ui.verticalSlider_7.valueChanged.connect(self._7_slider)
        self.ui.verticalSlider_8.valueChanged.connect(self._8_slider)
        self.ui.verticalSlider_9.valueChanged.connect(self._9_slider)
        self.ui.verticalSlider_10.valueChanged.connect(self._10_slider)
    
    
    def read_and_parse_values(self, data_to_write: bytes, eq_prefix_1: bytes, eq_prefix_2: bytes):
        
        ###################### 
        # OFFSETS    float with 4 bytes
        # 62length
        # float preamp @ 0x16
        # float val1 @ 0x1c;
        # float val2 @ 0x22;
        # float val3 @ 0x28;
        # float val4 @ 0x2E;
        # float val5 @ 0x34;
        # float val6 @ 0x3A;

        # 34length
        # float val7 @ 0x0c;
        # float val8 @ 0x12;
        # float val9 @ 0x18;
        # float val10 @ 0x1E;

                
        #print("##########################################  start ")

        ser.write(data_to_write)
        ser.flush()        
        
        #print("data to write: ", data_to_write.hex())
        
        eq_data_part_1 = ser.read_until(eq_prefix_1)    #8   54
  
        #print("prefix 1 found ", eq_prefix_1.hex()," -- " , eq_data_part_1.hex())
        eq_data_part_1 = ser.read(54) 
        eq_data_part_1 = eq_prefix_1 + eq_data_part_1
        
        #print("eqdata 1 len: ", len(eq_data_part_1), " - ", eq_data_part_1.hex())

        value_bytes = [0]*11

        value_bytes[10] = eq_data_part_1[0x16:0x1a]  #preamp
        value_bytes[0]  = eq_data_part_1[0x1c:0x20]
        value_bytes[1]  = eq_data_part_1[0x22:0x26]
        value_bytes[2]  = eq_data_part_1[0x28:0x2C]
        value_bytes[3]  = eq_data_part_1[0x2e:0x32]
        value_bytes[4]  = eq_data_part_1[0x34:0x38]
        value_bytes[5]  = eq_data_part_1[0x3a:0x3e]

        eq_data_part_2 = ser.read_until(eq_prefix_2)    #8   26
     
        #print("prefix 2 found ", eq_prefix_2.hex()," -- ",  eq_data_part_2.hex())
        eq_data_part_2 = ser.read(26) 
        eq_data_part_2 = eq_prefix_2 + eq_data_part_2

        #print("eqdata 2 len: ", len(eq_data_part_2), " - ", eq_data_part_2.hex() )

        value_bytes[6] = eq_data_part_2[0x0c:0x10]
        value_bytes[7] = eq_data_part_2[0x12:0x16]
        value_bytes[8] = eq_data_part_2[0x18:0x1C]
        value_bytes[9] = eq_data_part_2[0x1e: ]
        
        #print("timeouts: ", self.timeout_counter)
        
        #print("##########################################  end")
        
        if (len(eq_data_part_1) == 62) & (len(eq_data_part_2) == 34):
            
            for i in range(0, 11):
                self.value_float[i] = struct.unpack('f', value_bytes[i])[0]   #make floats from 4 bytes

            #print([ '%.1f' % elem for elem in self.value_float ]) #round list to x.x
            
            self.slider_connect_disconnect()
            
            self.ui.verticalSlider_1.setValue(self.value_float[0]*10)
            self.ui.verticalSlider_2.setValue(self.value_float[1]*10)
            self.ui.verticalSlider_3.setValue(self.value_float[2]*10)
            self.ui.verticalSlider_4.setValue(self.value_float[3]*10)
            self.ui.verticalSlider_5.setValue(self.value_float[4]*10)
            self.ui.verticalSlider_6.setValue(self.value_float[5]*10)
            self.ui.verticalSlider_7.setValue(self.value_float[6]*10)
            self.ui.verticalSlider_8.setValue(self.value_float[7]*10)
            self.ui.verticalSlider_9.setValue(self.value_float[8]*10)
            self.ui.verticalSlider_10.setValue(self.value_float[9]*10)
            self.ui.verticalSlider_preamp.setValue(self.value_float[10]*10)
            
            self.plot_view()
            
            self.slider_connect_connect()
  

        else:
            self.timeout_counter = self.timeout_counter +1
            print("##### bug #####")
            time.sleep(1)
            self.initialize_gui()
        
        self.ui.verticalSlider_1.label.setHidden(1)
        self.ui.verticalSlider_2.label.setHidden(1)
        self.ui.verticalSlider_3.label.setHidden(1)
        self.ui.verticalSlider_4.label.setHidden(1)
        self.ui.verticalSlider_5.label.setHidden(1)
        self.ui.verticalSlider_6.label.setHidden(1)
        self.ui.verticalSlider_7.label.setHidden(1)
        self.ui.verticalSlider_8.label.setHidden(1)
        self.ui.verticalSlider_9.label.setHidden(1)
        self.ui.verticalSlider_10.label.setHidden(1)
        self.ui.verticalSlider_preamp.label.setHidden(1)    

    
    
#################################################################        

class button_thread_(threading.Thread):   # just a thread which reads serial and captures buttons of the X4
 
    loop=1
    active = 1
    ready = 1

    buffer = collections.deque(maxlen=500)
    
    
    def __init__(self):
        threading.Thread.__init__(self)
        super(self.__class__, self).__init__()
        
    def get_last_bytes(self, number):  
        end_items=bytes.fromhex("")
        for i in range (-number, 0):
            end_items = end_items + bytes(self.buffer[i])
        return end_items
        
    def buffer_delete(self): # fills it up with "0"
        for i in range (0, 500):
            self.buffer.append(b'00')
        
    def run(self): 
    
        self.buffer_delete()
        print("button thread started")

        while(self.loop==1): 
        
            time.sleep(0.00001) #doesnt run without? 
            self.ready = 0
                        
            if self.active == 1:
                #byte = ser.read(1)
                #if byte:
                #    self.buffer.append(byte)
            
            
                try:
                    byte = ser.read(1)
                    if byte:
                        self.buffer.append(byte)
                except:
                    print("serial port exception")     #when i resume from hibernation of my pc i get error messages about the serial port not beeing ready and so on.... 
                    ser.close()         #and this dirty fix works for me
                    time.sleep(5)       #and unlocks X4 again after hibernation
                    open_serial_port()
                    input_after_hib = ser.read(500)
                    #print("input after hibernation: ", input_after_hib.hex())
                    unlock_device()
                    print("except end")
                    
            self.ready = 1
            


            if self.get_last_bytes(5) == answer_eq_1_is_active:
                #print("Button pressed -> Equalizer 1")
                self.buffer_delete()
                if prog.ui.comboBox_eqonoff.currentIndex() == 1:  #if eq off
                    prog.ui.comboBox_eq.setCurrentIndex(0)
                
            if self.get_last_bytes(5) == answer_eq_2_is_active:
                #print("Button pressed -> Equalizer 2")
                self.buffer_delete()
                prog.ui.comboBox_eq.setCurrentIndex(1)
                
            if self.get_last_bytes(5) == answer_eq_3_is_active:
                #print("Button pressed -> Equalizer 3")
                self.buffer_delete()
                prog.ui.comboBox_eq.setCurrentIndex(2)
                
            if self.get_last_bytes(13) == eq_ack:
                #print("Equalizer value changed acknowledge")
                self.buffer_delete()

            if self.get_last_bytes(16) == 2*answer_speakers:      #2x
                #print("Button pressed -> Speakers")
                self.buffer_delete()
                prog.ui.comboBox_sphp.setCurrentIndex(0)
                
            if self.get_last_bytes(16) == 2*answer_headphones:    #2x
                #print("Button pressed -> Headphones")
                self.buffer_delete()
                prog.ui.comboBox_sphp.setCurrentIndex(1)

            if self.get_last_bytes(11) == answer_eq_off:
                #print("Button pressed -> Equalizer Off")
                self.buffer_delete()
                prog.ui.comboBox_eqonoff.setCurrentIndex(1)
                
            if self.get_last_bytes(11) == answer_eq_on:
                #print("Button pressed -> Equalizer On")
                self.buffer_delete()
                prog.ui.comboBox_eqonoff.setCurrentIndex(0)
     
                
        
        print("thread ended")
     

#########################################
########################################


if __name__ == '__main__':

    print("Hello")
  
    app = QApplication(sys.argv)
    
    #app.setStyle("Breeze")
    
    prog = MainWindow()
    
    prog.show()
    
    ###########################
    open_serial_port()
    
    print("Authenticate to the X4")
    unlock_device()
    
    ###########################
    
    button_thread = button_thread_()    #Thread start
    button_thread.daemon=True
    button_thread.start()
    
    ############################
    
    prog.initialize_gui()
    
    

    ##########################
 
    app.exec()      #prog start
           
    ###########################     #Thread stop
                                
    if (button_thread.is_alive()==True): #if defined and active
        button_thread.loop=0
        print("button thread getting closed")
        button_thread.join()
        
    print("exit")
    
    ser.close()



