#import sys
import time
import errno
#import threading
#import binascii

import usb.core
import usb.util


TIMEOUT = 1000

#http://www.argenox.com/a-ble-advertising-primer/
#https://github.com/andrewdodd/ccsniffpiper/blob/master/ccsniffpiper.py
#https://github.com/christianpanton/ccsniffer/blob/master/ccsniffer.py

DEFAULT_CHANNEL = 0x0b # 11

DATA_EP_CC2531 = 0x83
DATA_EP_CC2530 = 0x82
DATA_EP_CC2540 = 0x83
DATA_TIMEOUT = 2500

GET_IDENT = 0xC0
SET_POWER = 0xC5
GET_POWER = 0xC6
SET_START = 0xD0
SET_END = 0xD1
SET_CHAN = 0xD2 # 0x0d (idx 0) + data)0x00 (idx 1)
DIR_OUT = 0x40
DIR_IN  = 0xc0
    
POWER_RETRIES = 10

dev = None
name = ""

def init():
	global dev 
	global name

	try:
		print('try CC2531')
		dev = usb.core.find(idVendor=0x0451, idProduct=0x16ae)
		if dev is None:
			print('did not find a CC2531')
	except usb.core.USBError:
		raise OSError("Permission denied, you need to add an udev rule for this device", errno=errno.EACCES)
    
	if dev is None:
		try:
			print('try CC2530')
			dev = usb.core.find(idVendor=0x11a0, idProduct=0xeb20)
			if dev is None:
				print('did not find a CC2530')
		except usb.core.USBError:
			raise OSError("Permission denied, you need to add an udev rule for this device", errno=errno.EACCES)

	if dev is None:
		try:
			print('try CC2540')
			dev = usb.core.find(idVendor=0x0451, idProduct=0x16b3)
			if dev is None:
				print('did not find a CC2540')
		except usb.core.USBError:
			raise OSError("Permission denied, you need to add an udev rule for this device", errno=errno.EACCES)


	if dev is None:
		#raise IOError("Device not found")
		print('Device not found')
		return

	dev.set_configuration() # must call this to establish the USB's "Config"
	#name = usb.util.get_string(dev, 256, 2) # get name from USB descriptor
	# get name from USB descriptor
	name = usb.util.get_string(dev,dev.iProduct)
	print('name')
	print(name)
	# get identity from Firmware command
	ident = dev.ctrl_transfer(DIR_IN, GET_IDENT, 0, 0, 256) # get identity from Firmware command
	print('ident')
	print(ident)

	# power on radio, wIndex = 4
	dev.ctrl_transfer(DIR_OUT, SET_POWER, wIndex=4)

	print('powering up')
	while True:
		# check if powered up
		power_status = dev.ctrl_transfer(DIR_IN, GET_POWER, 0, 0, 1)
		if power_status[0] == 4: break
		time.sleep(0.1)
	print('powered up')

	print('set channel to 37')#bt channel
	#channels 37,38,39 are the advertisement channels for BTLE
	set_channel(37)
	print('post channel')


def set_channel(channel):
	global dev

	print('set channel')

	dev.ctrl_transfer(DIR_OUT, SET_CHAN, 0, 0, [channel])
        dev.ctrl_transfer(DIR_OUT, SET_CHAN, 0, 1, [0x00])

	print('done setting channel')

def read_data():
	global dev
	print('start sniffing')
	dev.ctrl_transfer(DIR_OUT, SET_START)

	ctr=0

	#newFile = open("btle.dump", "wb")

	while True:
		print('get data')
		ret = dev.read(DATA_EP_CC2540, 4096, DATA_TIMEOUT)
		print('got data')
		print(ret)

		#newFile.write(ret)

		for x in ret:
			print ('%02X' % x),
#			print(x)
		print

		for x in ret:
			if x >= 0x20 and x <= 0x7D:
				print chr(x),
		print
	
		ctr = ctr + 1

		if ctr == 100:
			break
	#	break

	#newFile.close()


if __name__ == "__main__":
	init()
	read_data()

