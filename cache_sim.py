# jdh 2-24-24 my solution to the part one

from enum import Enum

WORDLENGTH = 4

# some specific values
MEMORY_SIZE = 65536  # 2^16
CACHE_SIZE = 1024  # 2^10
CACHE_BLOCK_SIZE = 64  # 2^6
ASSOCIATIVITY = 1  # direct mapped
WRITE_TYPE = 0  # write through

NUM_SETS = (CACHE_SIZE // (CACHE_BLOCK_SIZE * ASSOCIATIVITY))
NUM_BLOCKS = (CACHE_SIZE // CACHE_BLOCK_SIZE)

# a few globals, will be set later
memory_size_bits = 0
cache = None
memory = bytearray(MEMORY_SIZE)

#======================================================================
# for part one, we need only reads

class WriteType(Enum):
    THROUGH = 0
    BACK = 1


class AccessType(Enum):
    READ = 0
    WRITE = 1

#======================================================================

class CacheBlock:
    def __init__(self, cache_block_size):
        self.tag = -1
        self.dirty = False
        self.valid = False
        self.data = bytearray(cache_block_size)

#======================================================================
# strictly speaking, don't need a tag queue for part one

class CacheSet:
    def __init__(self, cache_block_size, associativity):
        self.blocks = [CacheBlock(cache_block_size) for i in range(associativity)]
        self.tag_queue = [-1 for i in range(associativity)]

#======================================================================

class Cache:
    def __init__(self, num_sets, associativity, cache_block_size, write_type):
        self.sets = [CacheSet(cache_block_size, associativity) \
                     for i in range(num_sets)]
        memory_size_bits = logb2(MEMORY_SIZE)
        self.cache_size_bits = logb2(CACHE_SIZE)
        self.cache_block_size_bits = logb2(CACHE_BLOCK_SIZE)
        self.index_length = logb2(NUM_SETS)
        self.block_offset_length = logb2(CACHE_BLOCK_SIZE)
        self.write_type = write_type

        print('-----------------------------------------')
        print(f'cache size = {CACHE_SIZE}')
        print(f'block size = {CACHE_BLOCK_SIZE}')
        print(f'#blocks = {NUM_BLOCKS}')
        print(f'#sets = {NUM_SETS}')
        print(f'associativity = {ASSOCIATIVITY}')
        print(f'tag length = {16 - self.index_length - self.block_offset_length}')
        print('-----------------------------------------')
        print()

#======================================================================
# helper function: log base two, in integer arithmetic

def logb2(val):
    i = 0
    assert val > 0
    while val > 0:
        i = i + 1
        val = val >> 1
    return i - 1

#======================================================================
# helper function

def binary_to_string(addrlen, val):
    bits = ''
    for i in range(addrlen):
        bit = val & 1
        if bit == 0:
            bits = '0' + bits
        else:
            bits = '1' + bits
        val = val // 2

    return bits

#======================================================================
# convert the four bytes in source[start:start+size] to a
# little-endian integer

def bytes_to_word(source, start, size):
    word = 0
    mult = 1
    for i in range(size):
        word = word + mult * source[start + i]
        # print(f'source[{start+i}] = {source[start+i]}; word is now {word}')
        mult = mult * 256
    return word

#======================================================================
# convert the integer in word to a little-endian byte sequence
# and put it in dest[start:start+size]

def word_to_bytes(dest, start, word, size):
    for i in range(size):
        v = word % 256
        dest[i + start] = v
        word = word // 256

#======================================================================
# access_type is READ or WRITE
# word is unused for READ; word is the actual data for WRITE

def memory_access(address, word, access_type):
    assert address < MEMORY_SIZE
    if address & 0x3 != 0:
        print(f'alignment error! address={address}')
        assert address & 0x3 == 0

    # example calculations
    # if there are 8 sets:
    # index is 3 bits: 1024 / (8*64); it's the set number
    # blockIndex will be the first block in the set
    # block offset is 6 bits
    # so tag is 16 - 3 - 6 = 7 bits
    #
    # if there are 4 sets:
    # index is 2 bits: 1024 / (4*64); it's the set number
    # blockIndex will be the first block in the set
    # block offset is 6 bits
    # so tag is 16 - 2 - 6 = 8 bits

    tag = address >> (cache.index_length + cache.block_offset_length)

    # index is the set number
    index = (address // CACHE_BLOCK_SIZE) & (NUM_SETS - 1)
    # offset in block is lowest bits
    block_offset = address & (CACHE_BLOCK_SIZE - 1)

    range_low = (address >> cache.cache_block_size_bits) * CACHE_BLOCK_SIZE
    range_high = range_low + CACHE_BLOCK_SIZE - 1

    found = False
    block_index = 0
    if cache.sets[index].blocks[block_index].tag == tag:
        found = True

    # READ:
    # if tag is found and the block is valid, then get the value and done
    # else
    #   // need to read a block from memory
    #   if there is a free block in this set, then read
    #   else find a target block and replace
    #
    # WRITE:
    # if tag is found then write to cache
    # else
    #   if there is a free block, then read the block in and write the value
    #   else find a target block and replace and then write the value

    if found:
        # CACHE HIT
        if access_type == AccessType.READ:
            # TODO: Read hit
            if not cache.sets[index].blocks[block_index].valid:
                print('error: tag found in cache, but block is not valid')
                assert cache.sets[index].blocks[block_index].valid

            # the word we want from the cache starts at
            # cache.sets[index].blocksp[block_index].data[block_offset]
            memval = bytes_to_word(
                source=cache.sets[index].blocks[block_index].data,
                start=block_offset, size=WORDLENGTH)
            print(f'read hit [addr={address} index={index} block_index={block_index} tag={tag}: word={memval} ({range_low} - {range_high}]')

            # put tag in the tag queue -- for associative cache
            for i in range(len(cache.sets[index].tag_queue)):
                if cache.sets[index].tag_queue[i] == tag:
                    cache.sets[index].tag_queue.pop(i)
                    break
                cache.sets[index].tag_queue.pop(len(cache.sets[index].tag_queue) - 1)

            cache.sets[index].tag_queue.insert(0, tag)

        # TODO: Write hit
        else:
            # write the word to the cache strting at
            # cache.sets[index].blocks[block_index].data[block_offset]
            word_to_bytes(dest=cache.sets[index].blocks[block_index].data,
                          start=block_offset, word=word, size=WORDLENGTH)

            # for part two check whether this is a write-through cache
            # if write through
            if cache.write_type == WriteType.THROUGH:
                # TODO: Write through
                write_to_data(cache.sets[index].blocks[block_index].data, block_offset, word, WORDLENGTH)
                write_to_memory(address, word)
            else:
                # TODO: Write back
                if not cache.sets[index].blocks[block_index].dirty and cache.sets[index].blocks[block_index].valid:
                    cache.sets[index].blocks[block_index].dirty = True

                # Set the tag and valid flag for this block
                cache.sets[index].blocks[block_index].tag = tag
                cache.sets[index].blocks[block_index].valid = True

                # Update the tag queue for this set
                cache.sets[index].tag_queue.remove(tag)
                cache.sets[index].tag_queue.insert(0, tag)

                memval = None

        return memval

    else:
        # CACHE MISS
        # TODO: Choose block to use
        free_block = None
        # Try to find an unused block
        for i in range(len(cache.sets[index].blocks)):
            # Check if any blocks aren't valid
            if not cache.sets[index].blocks[i].valid:
                # Invalid block found, use this block
                # Update the tag queue for this set
                cache.sets[index].tag_queue.remove(tag)
                cache.sets[index].tag_queue.insert(0, tag)
                # set to valid
                cache.sets[index].blocks[block_index].valid = True
                free_block = i
                if access_type == AccessType.READ:
                    memval =read_from_memory(address, CACHE_BLOCK_SIZE)
                    cache.sets[index].blocks[free_block].data = memval
                    print(f'read hit [addr={address} index={index} block_index={block_index} tag={tag}: word={memval} ({range_low} - {range_high}]')

                else:
                    # Write back
                    if cache.write_type == WriteType.BACK:
                        word_to_bytes(dest=cache.sets[index].blocks[free_block].data,
                                      start=block_offset, word=word, size=WORDLENGTH)

                        # Set the dirty flag for this block
                        cache.sets[index].blocks[free_block].dirty = True
                        # Set the tag for this block
                        cache.sets[index].blocks[free_block].tag = tag
                    # Write through
                    else:
                        word_to_bytes(dest=memory,
                                      start=)

                break

        # if no invalid blocks, replace the least recently used block
        # must evict a block
        if free_block is None:
            # Write the contents of block to be replaced to memory
            write_to_memory()
            # get tag for block to be replaced and remove from queue
            # Find least recently used block
            old_block_tag = cache.sets[index].tag_queue.pop()
            # get its index
            for i in range(len(cache.sets[index].blocks)):
                if cache.sets[index].blocks[i].tag == old_block_tag:
                    block_index = i

            # insert tag for new block into tag queue
            cache.sets[index].tag_queue.insert(0, tag)


            # TODO: Read miss for overwriting block
            if access_type == AccessType.READ:
                cache.sets[index].blocks[block_index].data = read_from_memory(address, CACHE_BLOCK_SIZE)


            else:
                # TODO: Write miss
                # TODO: Write through
                if cache.write_type == WriteType.THROUGH:
                    write_to_memory(address, word)
                    word_to_bytes(dest=cache.sets[index].blocks[free_block].data,
                                  start=block_offset, word=word, size=WORDLENGTH)
                # TODO: Write back
                else:
                    word_to_bytes(dest=cache.sets[index].blocks[free_block].data,
                                  start=block_offset, word=word, size=WORDLENGTH)
                    if not cache.sets[index].blocks[block_index].dirty and cache.sets[index].blocks[block_index].valid:
                        cache.sets[index].blocks[block_index].dirty = True

    # otherwise, we have cache miss
    # this will be handled in part two
    # check whether there is a free block; if not, then need to replace
    # etc.

    return None

    # TODO: When evicting a block marked dirty in write back cache, write contents of block to memory before evicting

#======================================================================


def write_to_data(data, start, word, size):
    for i in range(size):
        v = word % 256
        data[i + start] = v
        word = word // 256

def write_to_memory(address, word):
    # Convert the word to bytes
    data = bytearray(WORDLENGTH)
    word_to_bytes(data, 0, word, WORDLENGTH)

    # Write the data to memory
    start_address = (address // CACHE_BLOCK_SIZE) * CACHE_BLOCK_SIZE
    memory[start_address:start_address + CACHE_BLOCK_SIZE] = data

def read_from_memory(address, block_size):
    start_address = (address // block_size) * block_size
    return memory[start_address:start_address + block_size]


def read_word(address):
    return memory_access(address, None, AccessType.READ)

#======================================================================

def write_word(address, word):
    memory_access(address, word, AccessType.WRITE)

#======================================================================

def testF():
    # direct mapped, preloaded cache
    addr = 4 + (13 << 6) + (45 << 10)
    word_to_bytes(cache.sets[13].blocks[0].data, 4, addr, WORDLENGTH)
    cache.sets[13].blocks[0].valid = True
    cache.sets[13].blocks[0].tag = 45
    word = read_word(addr)
    print(f'address = {addr} {binary_to_string(16, addr)}; word = {word}')
    print()

    addr = 12 + (81 << 6) + (1 << 13)
    word_to_bytes(cache.sets[1].blocks[0].data, 12, addr, WORDLENGTH)
    cache.sets[1].blocks[0].valid = True
    cache.sets[1].blocks[0].tag = 13
    word = read_word(addr)
    print(f'address = {addr} {binary_to_string(16, addr)}; word = {word}')
    print()

#======================================================================

def main():
    global cache
    cache = Cache(NUM_SETS, ASSOCIATIVITY, CACHE_BLOCK_SIZE, 0)

    # prefill memory: the word at memory[a] will be a
    for i in range(MEMORY_SIZE // 4):
        word_to_bytes(dest=memory, start=4 * i, word=4 * i, size=WORDLENGTH)

    testF()

#======================================================================

main()
