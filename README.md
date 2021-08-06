# UF2 Loader for IDA

The DEFCON 29 badge uses the UF2 bootloader, which conveniently allows you to dump and flash the firmware over USB as a mass storage device, so when you plug it into your computer in the right mode it shows up like a flash drive.

A detailed spec of the UF2 file format can be found [here](https://github.com/microsoft/uf2).

## Installation

To install, simply copy the [uf2.py](uf2.py) file into IDA's `loaders` directory. Then, whenever you load a UF2 file, it will be detected and IDA will understand how to load it.

## Limitations

For now, due to laziness, the processor is just assumed to be ARM 32-bit. The DEFCON badge uses the SAMD21G16B processor, and an SVD file describing memory layout and such can be found [here](https://github.com/posborne/cmsis-svd/blob/master/data/Atmel/ATSAMD21G16B.svd).

## Standalone usage

The [uf2.py](uf2.py) script can also be invoked directly from the command line to convert a UF2 file into a flat firmware binary. To use it as such, run: `python3 uf2.py firmware.uf2 output.bin`

-----

Thanks to the [ghidra_uf2loader](https://github.com/wyattearp/ghidra_uf2loader) project for inspiration and some help with understanding the format.