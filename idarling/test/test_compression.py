# https://docs.python.org/3/library/bz2.html#examples-of-usage
# https://www.programcreek.com/python/example/6089/bz2.BZ2Decompressor

import bz2, hexdump

original_data = b"abc" * 1000


def gen_data(data, chunk_size=1000):
    """Yield incremental blocks of chunksize bytes."""
    len_data = len(data)
    total_count_sent = 0
    for i in range(int(len_data / chunk_size)):
        yield data[chunk_size * i : chunk_size * (i + 1)]
    if len_data % chunk_size != 0:
        yield data[-(len_data % chunk_size) :]
    else:
        yield b""


comp = bz2.BZ2Compressor()
out = b""
for chunk in gen_data(original_data):
    out = out + comp.compress(chunk)

# Finish the compression process.  Call this once you have
# finished providing data to the compressor.
out = out + comp.flush()

hexdump.hexdump(out)
print("-" * 30)


decomp = bz2.BZ2Decompressor()
data_decompressed = b""
for chunk in gen_data(out):
    data_decompressed += decomp.decompress(chunk)

print(len(data_decompressed))
hexdump.hexdump(data_decompressed[:100])
