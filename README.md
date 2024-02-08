# dump-option-roms
Python script to dump Option ROMs from Linux

```
usage: dump-option-roms.py [-h] [--start-addr START_ADDR]
                           [--end-addr END_ADDR] [--step STEP]
                           [--force-size FORCE_SIZE] [-j] [-o FILE]
                           (-l | -d ADDRESS | --dump-all DIRECTORY)

read BIOS option ROMs

options:
  -h, --help            show this help message and exit
  --start-addr START_ADDR
                        start address, default: 0xC0000
  --end-addr END_ADDR   end address, default: 0xF5FFF
  --step STEP           enumerate in steps of this many bytes,
                        default: 0x800
  --force-size FORCE_SIZE
                        override ROM size (use with --dump)
  -j, --json            output JSON
  -o FILE, --output FILE
                        output file, default: stdout
  -l, --list            list option ROMs
  -d ADDRESS, --dump ADDRESS
                        dump ROM at the specified address
  --dump-all DIRECTORY  dump all detected ROMS into the specified
                        directory
```
