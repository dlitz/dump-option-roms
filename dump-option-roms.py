#!/usr/bin/env python
# SPDX-License-Identifier: MIT
# Copyright 2024 Darsey Litzenberger <dlitz@dlitz.net>
# Ref: https://en.wikipedia.org/wiki/Option_ROM
# This is compatible with Python 2.7 and Python 3

from argparse import ArgumentParser
import struct
import json
import sys
import math
import os
from zlib import crc32
from logging import getLogger
from io import StringIO

DEFAULT_START_ADDR = 0xC0000
DEFAULT_END_ADDR = 0xF5FFF	# 0xF4000 + 8192 - 1
DEFAULT_STEP = 0x800		# 2 KiB steps

globalLogger = getLogger(__name__)

class ROMSignatureError(Exception):
	pass

class StdoutTtyError(Exception):
	pass

class MemoryDevice(object):
	def __init__(self):
		self._f = open("/dev/mem", "rb", 0)

	def __del__(self):
		self.close()

	def __enter__(self):
		return self

	def __exit__(self, *args):
		self.close()

	def close(self):
		return self._f.close()

	def _pread(self, size, offset):
		self._f.seek(offset)
		return self._f.read(size)

	def read_bytes(self, offset, size):
		return self._pread(size, offset)

	def read_cstr_raw(self, offset):
		buf = []
		b = 1
		while b != 0:
			b = self.read_u8(offset)
			buf.append(b)
			offset += 1
		return b''.join(buf)

	def read_ncstr_utf8(self, offset):
		s = self.read_cstr_raw(offset)
		assert s[-1:] == b'\0'
		return len(s), s[:-1].decode('utf-8')

	def read_cstr_utf8(self, offset):
		return self.read_ncstr_utf8(offset)[1]
		
	def read_u8(self, offset):
		return struct.unpack("<B", self._pread(1, offset))[0]

	def read_s8(self, offset):
		return struct.unpack("<b", self._pread(1, offset))[0]

	def read_u16_le(self, offset):
		return struct.unpack("<H", self._pread(2, offset))[0]

	def read_s16_le(self, offset):
		return struct.unpack("<h", self._pread(2, offset))[0]

	def read_u32_le(self, offset):
		return struct.unpack("<L", self._pread(4, offset))[0]

	def read_s32_le(self, offset):
		return struct.unpack("<l", self._pread(4, offset))[0]

	def read_u64_le(self, offset):
		return struct.unpack("<Q", self._pread(8, offset))[0]

	def read_s64_le(self, offset):
		return struct.unpack("<q", self._pread(8, offset))[0]

	def read_u16_be(self, offset):
		return struct.unpack(">H", self._pread(2, offset))[0]

	def read_s16_be(self, offset):
		return struct.unpack(">h", self._pread(2, offset))[0]

	def read_u32_be(self, offset):
		return struct.unpack(">L", self._pread(4, offset))[0]

	def read_s32_be(self, offset):
		return struct.unpack(">l", self._pread(4, offset))[0]

	def read_u64_be(self, offset):
		return struct.unpack(">Q", self._pread(8, offset))[0]

	def read_s64_be(self, offset):
		return struct.unpack(">q", self._pread(8, offset))[0]

class MemoryAddress(object):

	def __init__(self, mem, offset=0):
		self._type = type(self)
		self._mem = mem
		self.offset = offset

	def __repr__(self):
		cls = type(self)
		clsname = cls.__name__
		return "<%s [0x%x]>" % (clsname, self.offset)

	def absolute(self, offset):
		return self._type(self._mem, offset)

	def __getitem__(self, offset):
		return self._type(self._mem, self.offset + offset)

	@property
	def u8(self):
		return self._mem.read_u8(self.offset)

	@property
	def s8(self):
		return self._mem.read_s8(self.offset)

	@property
	def u16le(self):
		return self._mem.read_u16_le(self.offset)

	@property
	def s16le(self):
		return self._mem.read_s16_le(self.offset)

	@property
	def u16be(self):
		return self._mem.read_u16_be(self.offset)

	@property
	def s16be(self):
		return self._mem.read_s16_be(self.offset)

	@property
	def u32le(self):
		return self._mem.read_u32_le(self.offset)

	@property
	def s32le(self):
		return self._mem.read_s32_le(self.offset)

	@property
	def u32be(self):
		return self._mem.read_u32_be(self.offset)

	@property
	def s32be(self):
		return self._mem.read_s32_be(self.offset)
	
	@property
	def u64le(self):
		return self._mem.read_u64_le(self.offset)

	@property
	def s64le(self):
		return self._mem.read_s64_le(self.offset)

	@property
	def u64be(self):
		return self._mem.read_u64_be(self.offset)

	@property
	def s64be(self):
		return self._mem.read_s64_be(self.offset)

	@property
	def cstr_raw(self):
		return self._mem.read_cstr_raw(self.offset)

	@property
	def cstr_utf8(self):
		return self._mem.read_cstr_raw(self.offset)

	@property
	def ncstr_utf8(self):
		return self._mem.read_ncstr_utf8(self.offset)

	def bytes(self, size):
		return self._mem.read_bytes(self.offset, size)

def align_down(addr, alignment):
	# Increase address in steps of 2 KiB
	return (addr // alignment) * alignment

def find_option_roms(mem, first_addr, last_addr, step, include_null=False):
	assert first_addr <= last_addr
	addr = first_addr
	min_size = 3
	while addr + min_size <= last_addr:
		assert first_addr <= addr, (first_addr, addr)
		if mem[addr].u16be == 0x55AA:
			size_blocks = mem[addr+2].u8
			size_bytes = size_blocks * 512
			if addr + size_bytes < last_addr:
				yield addr, size_bytes
			addr += size_bytes
		elif include_null:
			yield addr, None

		# Increment address
		addr = first_addr + align_down(addr - first_addr, step) + step

def pretty_size(n):
	q, r = divmod(n, 1024)
	if r == 0:
		return "%d KiB" % (q,)
	return "%d-byte" % (n,)

def read_option_rom_at(mem, addr, force_size=None):
	logger = globalLogger.getChild('read_option_rom_at')
	if force_size is not None:
		size_bytes = force_size
		logger.info("size forced to %d bytes", size_bytes)
	elif mem[addr].u16be == 0x55AA:
		size_blocks = mem[addr+2].u8
		size_bytes = size_blocks * 512
		logger.info("Detected %s ROM at address 0x%X", pretty_size(size_bytes), addr)
	else:
		raise ROMSignatureError("ROM signature not found at address 0x%X" % addr)
	if mem[addr].u16be != 0x55AA:
		logger.warning("ROM signature not found at address 0x%X (expected 55 AA, got %02X %02X)", addr, mem[addr].u8, mem[addr+1].u8)
	logger.info("Reading memory 0x%X-0x%X", addr, addr + size_bytes - 1)

	return mem[addr].bytes(size_bytes)

def parse_int(s):
	return int(s, 0)

def parse_args():
	parser = ArgumentParser(description="read BIOS option ROMs")
	parser.add_argument("--start-addr", type=parse_int, default=DEFAULT_START_ADDR, help="start address, default: 0x%(default)X")
	parser.add_argument("--end-addr", type=parse_int, default=DEFAULT_END_ADDR, help="end address, default: 0x%(default)X")
	parser.add_argument("--step", type=parse_int, default=DEFAULT_STEP, help="enumerate in steps of this many bytes")
	parser.add_argument("--force-size", type=parse_int, help="override ROM size (use with --dump)")
	g = parser.add_mutually_exclusive_group(required=True)
	g.add_argument("-l", "--list", action="store_true", help="list option ROMs")
	g.add_argument("-d", "--dump", metavar="ADDRESS", type=parse_int, help="dump ROM at the specified address")
	g.add_argument("--dump-all", metavar="DIRECTORY", help="dump all detected ROMS into the specified directory")
	parser.add_argument("-j", "--json", action="store_true", help="output JSON")
	parser.add_argument("-o", "--output", metavar="FILE", help="output file, default: stdout")
	args = parser.parse_args()
	if args.force_size and args.dump is None:
		parser.error("--force-size requires --dump")
	return args, parser

def main():
	args, parser = parse_args()
	init_logging()

	if args.list:
		cmd_list(args, parser)
	elif args.dump:
		cmd_dump(args, parser)
	elif args.dump_all:
		cmd_dump_all(args, parser)
	else:
		assert 0, args

def open_path_arg(path, mode):
	allow_stdout_tty = 'b' not in mode
	if path is None or str(path) == '-':
		if not allow_stdout_tty and os.isatty(1):
			raise StdoutTtyError("stdout is a tty")
		return os.fdopen(os.dup(1), mode)
	return open(path, mode)

def cmd_list(args, parser):
	logger = globalLogger.getChild('cmd_list')
	with MemoryDevice() as memdev, open_path_arg(args.output, 'w') as output:
		mem = MemoryAddress(memdev)
		if args.json:
			output.write("[")
		else:
			output.write("address\tsize\n")
		for i, (addr, size) in enumerate(find_option_roms(mem, args.start_addr, args.end_addr, args.step)):
			if args.json:
				if i:
					output.write(",\n")
				else:
					output.write("\n")
				output.write('\t{"address": 0x%X, "size": 0x%X}' % (addr, size))
			else:
				output.write("0x%X\t0x%X\n" % (addr, size))
		if args.json:
			output.write("\n]\n")

def cmd_dump(args, parser):
	logger = globalLogger.getChild('cmd_dump')
	with MemoryDevice() as memdev:
		mem = MemoryAddress(memdev)
		rom_data = read_option_rom_at(mem, args.dump, args.force_size)
		try:
			with open_path_arg(args.output, 'wb') as output:
				output.write(rom_data)
		except StdoutTtyError:
			sys.stderr.write("%s: error: cowardly refusing to write binary data to a tty\n" % (parser.prog,))
			sys.exit(2)
		crc = crc32(rom_data) & 0xFFFFFFFF
		logger.info("CRC32 checksum: 0x%X", crc)
		if args.output is None:
			logger.info("Wrote %d bytes to standard output", len(rom_data))
		else:
			logger.info("Wrote %d bytes to file: %s", len(rom_data), args.output)

def make_filename(addr, size, n=-1):
	start_addr = addr
	end_addr = addr + size - 1
	assert start_addr <= end_addr, (start_addr, end_addr, size)
	n = max(n, len("%X" % end_addr))
	fmt = "%" + str(n) + "X"
	start_addr_str = fmt % (start_addr,)
	end_addr_str = fmt % (end_addr,)
	return "rom-%s-%s.bin" % (start_addr_str, end_addr_str)

def cmd_dump_all(args, parser):
	logger = globalLogger.getChild('cmd_dump_all')
	output_dir = args.dump_all
	if not os.path.exists(output_dir):
		os.mkdir(output_dir)
	with MemoryDevice() as memdev, open_path_arg(args.output, 'w') as real_output, StringIO() as output:
		mem = MemoryAddress(memdev)
		found_roms = list(find_option_roms(mem, args.start_addr, args.end_addr, args.step))
		if args.force_size is not None:
			n_digits = len("%X" % (args.force_size,))
		else:
			n_digits = max(len("%X" % (addr + size - 1,)) for addr, size in found_roms)
		if args.json:
			output.write(u"[")
		else:
			output.write(u"address\tsize\tCRC-32_checksum\tfilename\n")
		for i, (addr, size) in enumerate(found_roms):
			rom_data = read_option_rom_at(mem, addr, args.force_size)
			if args.force_size is not None:
				assert len(rom_data) == force_size
			else:
				assert len(rom_data) == size
			size = len(rom_data)
			filename = make_filename(addr, size, n_digits)
			pathname = os.path.join(output_dir, filename)
			with open(pathname, 'wb') as outfile:
				outfile.write(rom_data)
			crc = crc32(rom_data) & 0xFFFFFFFF
			if args.json:
				if i:
					output.write(u",\n")
				else:
					output.write(u"\n")
				output.write(u'\t{"address": 0x%X, "size": 0x%X, "crc32": 0x%X, "filename": %s}' % (addr, size, crc, json.dumps(filename)))
			else:
				output.write(u"0x%X\t0x%X\t0x%X\t%s\n" % (addr, size, crc, filename))
		if args.json:
			output.write(u"\n]\n")
		real_output.write(output.getvalue())

def init_logging():
	import logging
	logging.basicConfig(level=logging.INFO, format="* %(message)s")

if __name__ == '__main__':
	main()

# vim:set sw=8 sts=8 noet:
