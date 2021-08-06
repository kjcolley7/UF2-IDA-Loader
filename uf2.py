if __name__ != "__main__":
	from idaapi import *
	from idc import *
	
	import idaapi
	import idc

import struct
import os

def u32(s):
	return struct.unpack("<I", s)[0]

UF2_BLOCK_SIZE = 0x200
UF2_FIRST_MAGIC = 0x0A324655
UF2_SECOND_MAGIC = 0x9E5D5157
UF2_FINAL_MAGIC = 0x0AB16F30
UF2_DATA_BLOCK_SIZE = 0x1dc
UF2_BLOCK_DATA_OFFSET = 0x20

UF2_FAMILY_ID_MAP = {
	0x16573617: "Microchip (Atmel) ATmega32",
	0x1851780a: "Microchip (Atmel) SAML21",
	0x1b57745f: "Nordic NRF52",
	0x1c5f21b0: "ESP32",
	0x1e1f432d: "ST STM32L1xx",
	0x202e3a91: "ST STM32L0xx",
	0x21460ff0: "ST STM32WLxx",
	0x2abc77ec: "NXP LPC55xx",
	0x300f5633: "ST STM32G0xx",
	0x31d228c6: "GD32F350",
	0x04240bdf: "ST STM32L5xx",
	0x4c71240a: "ST STM32G4xx",
	0x4fb2d5bd: "NXP i.MX RT10XX",
	0x53b80f00: "ST STM32F7xx",
	0x55114460: "Microchip (Atmel) SAMD51",
	0x57755a57: "ST STM32F401",
	0x5a18069b: "Cypress FX2",
	0x5d1a0a2e: "ST STM32F2xx",
	0x5ee21072: "ST STM32F103",
	0x647824b6: "ST STM32F0xx",
	0x68ed2b88: "Microchip (Atmel) SAMD21",
	0x6b846188: "ST STM32F3xx",
	0x6d0922fa: "ST STM32F407",
	0x6db66082: "ST STM32H7xx",
	0x70d16653: "ST STM32WBxx",
	0x7eab61ed: "ESP8266",
	0x7f83e793: "NXP KL32L2x",
	0x8fb060fe: "ST STM32F407VG",
	0xada52840: "Nordic NRF52840",
	0xbfdd4eee: "ESP32-S2",
	0xc47e5767: "ESP32-S3",
	0xd42ba06c: "ESP32-C3",
	0xe48bff56: "Raspberry Pi RP2040",
	0x00ff6919: "ST STM32L4xx",
}

class UF2Header(object):
	def __init__(self, f):
		self.m_magicStart0 = u32(f.read(4))
		self.m_magicStart1 = u32(f.read(4))
		self.m_flags = u32(f.read(4))
		self.m_targetAddr = u32(f.read(4))
		self.m_payloadSize = u32(f.read(4))
		self.m_blockNo = u32(f.read(4))
		self.m_numBlocks = u32(f.read(4))
		self.m_fileSize = u32(f.read(4))
		self.m_data = f.read(UF2_DATA_BLOCK_SIZE)
		self.m_magicEnd = u32(f.read(4))
	
	def get_processor(self):
		matches = 0
		if self.m_magicStart0 == UF2_FIRST_MAGIC:
			matches += 1
		
		if self.m_magicStart1 == UF2_SECOND_MAGIC:
			matches += 1
		
		if self.m_magicEnd == UF2_FINAL_MAGIC:
			matches += 1
		
		if matches == 0:
			return None
		
		processor = "unknown"
		if self.m_flags & 0x2000:
			if self.m_fileSize in UF2_FAMILY_ID_MAP:
				processor = UF2_FAMILY_ID_MAP[self.m_fileSize]
		
		return processor

class FlatFile(object):
	def __init__(self):
		self.data = []
	
	def add_data(self, address, bs):
		extra = address + len(bs) - len(self.data)
		if extra > 0:
			self.data.extend([0] * extra)
		
		self.data[address:address+len(bs)] = bs

def accept_file(f, n):
	if idaapi.IDA_SDK_VERSION < 700:
		if n != 0:
			return 0
	
	try:
		header = UF2Header(f)
		processor = header.get_processor()
		if processor is not None:
			print("UF2 file detected [%s]: processor is %s" % (n, processor))
			return "UF2 - " + processor
	except Exception(e):
		print("UF2 exception: %s" % e)
		pass
	
	
	print("Not a UF2 file")
	return 0


def load_file(f, neflags, format):
	f.seek(0)
	
	header = UF2Header(f)
	idaapi.set_processor_type("arm", 1) # SETPROC_LOADER == SETPROC_ALL == 1
	
	ff = FlatFile()
	
	for i in range(header.m_numBlocks):
		print("Reading block %#x" % i)
		
		f.seek(i * UF2_BLOCK_SIZE)
		chunk = UF2Header(f)
		
		print("Data: %#x - %#x" % (chunk.m_targetAddr, chunk.m_targetAddr + chunk.m_payloadSize))
		
		f.file2base(i * UF2_BLOCK_SIZE + UF2_BLOCK_DATA_OFFSET, chunk.m_targetAddr, chunk.m_targetAddr + chunk.m_payloadSize, True)
		ff.add_data(chunk.m_targetAddr, chunk.m_data[:chunk.m_payloadSize])
	
	idaapi.add_segm(0, 0, len(ff.data), "FIRMWARE", "CODE")
	
	# Additional memory layout should be populated using the processor's SVD file:
	# https://github.com/posborne/cmsis-svd/blob/master/data/Atmel/ATSAMD21G16B.svd
	
	# IDA >= 7.5 has a plugin for loading processor info (constants, registers, memory maps)
	# from an SVD file.
	
	return 1

if __name__ == "__main__":
	import sys
	if len(sys.argv) != 3:
		print("Usage: %s firmware.uf2 output.bin" % sys.argv[0])
		sys.exit(1)
	
	with open(sys.argv[1], "rb") as f:
		ff = FlatFile()
		hdr = UF2Header(f)
		
		for i in range(hdr.m_numBlocks):
			f.seek(i * UF2_BLOCK_SIZE)
			chunk = UF2Header(f)
			ff.add_data(chunk.m_targetAddr, chunk.m_data[:chunk.m_payloadSize])
		
		with open(sys.argv[2], "wb") as fout:
			fout.write(bytes(ff.data))
