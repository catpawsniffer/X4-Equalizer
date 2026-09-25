# X4 Equalizer for Linux

**A simple Python Program with Gui to Control the Equalizer of the X4 Soundblaster**

You can only configure the Equalizer. All the fancy rest like SXFI and so is not supported. I think no one needs that stuff. And in general the X4 is fully supported by the standard drivers of Linux to play sound and set up speaker configurations and so on.

![enter image description here](https://github.com/catpawsniffer/X4-Equalizer/blob/main/x4-screenshot_1.png)

##

**Serial Port and access rights**

Make sure you have access to serial interfaces like /dev/tty* 
The X4 will show up something like /dev/ttyACM0 (these are the serial ports over usb)
Access is most often managed via udev rules.
How to do this depends on your distribution. 
I uploaded 2 udev rule files from me. I guess they work for all Arch derivations like Cachyos.
Or just do a dirty chmod777 on the /dev/ttyACM* to test it out...
##
**I compiled everything into an executable file, including all dependencies.**

Download and execute. Have fun
##

**If you want to run the python script directly**

You will need python 3 and the needed libraries/dependencies listed in requirements.txt
Most distributions use their package manager like pacman to download these. And some allow/block you to use pip to download.
Alternatively you can also use pip to install dependencies into a virtual environment.

**To install all dependencies to a virtual environment:**
```
python -m venv venv
source venv/bin/activate     
python -m pip install -r requirements.txt
python x4-equalizer.py
```
If you use fish Shell like me in Cachyos:
```
python -m venv venv
source venv/bin/activate.fish     
python -m pip install -r requirements.txt
python x4-equalizer.py
```
**To run x4-equalizer:**
```
source venv/bin/activate
python x4-equalizer.py
```
If you use fish Shell like me in Cachyos:
```  
source venv/bin/activate.fish  
python x4-equalizer.py  
```
##
**A word about the Challenge - Response Authentication**

The X4 uses some kind of challenge - response authentication so only the official software from Creative can work with the X4. or so.....
To be honest. I used AI to get the info about the encryption and extract the secret key from CTCDC.dll (part of creative "drivers")

AES-256
GCM-Mode
16 Byte IV-Field (random numbers)
32 Byte Ciphertext
16 Byte Authentication Tag
GCM Nonce = first 12 Bytes of IV
```
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#The PC App sends this to the X4: "whoareyou.MyApp8\r\n"
#The X4 replies with the challenge

STATIC_KEY_MIDDLE = bytes.fromhex(
        "d3 1a 21 27 9b e3 46 f0 99 9d 6e c4 c3 fe "
        "be 98 90 18 69 c1 18 fb b1 25 6e 0c e0 7b") #28 bytes
        
c_prefix = challenge_packet[0:9]     #"whoareyou"
c_header = challenge_packet[9:13]    #4 byte -> key
challenge = challenge_packet[13:45]  #32 byte  

#The complete key is:
key = c_header[0:2] + STATIC_KEY_MIDDLE + c_header[2:4] #32 bytes

# Convert the 32-byte X4 challenge nonce into:
# "unlock" + IV(16) + ciphertext(32) + tag(16) + b"\r\n"
# Creative uses a 16-byte IV, with the first 12 bytes becoming
# the actual GCM nonce.

iv = os.urandom(16)
gcm_nonce = iv[:12]
aes = AESGCM(key)
encrypted = aes.encrypt(gcm_nonce, challenge, None)

# cryptography's AESGCM.encrypt() returns:
# ciphertext || 16-byte authentication tag

ciphertext = encrypted[:-16] #32 bytes
tag = encrypted[-16:]        #16 bytes

return (            #full response packet
    UNLOCK_PREFIX   #"unlock"
    + iv            #16 byte
    + ciphertext    #32 byte
    + tag           #16 byte
    + CRLF          #CRLF = b"\r\n" 
)

#The X4 should reply with "unlock_OK"
```

##
Uses Qt-6 library https://www.qt.io/development/qt-framework/qt6
