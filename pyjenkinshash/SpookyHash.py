

def spookyrot64(x, k):
    return ((x << k) & MASK64) | (x >> (64 - k))

    # This is used if the input is 96 bytes long or longer.
    #
    # The internal state is fully overwritten every 96 bytes.
    # Every input bit appears to cause at least 128 bits of entropy
    # before 96 other bytes are combined, when run forward or backward
    #   For every input bit,
    #   Two inputs differing in just that input bit
    #   Where "differ" means xor or subtraction
    #   And the base value is random
    #   When run forward or backwards one Mix
    # I tried 3 pairs of each; they all differed by at least 212 bits.
    #
def spookymix(data, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11):
    s0 += int.from_bytes(data[0*8 : 1*8], 'big')
    s0 &= MASK64
    s2 ^= s10
    s11 ^= s0
    s0 = spookyrot64(s0,11)
    s11 += s1
    s11 &= MASK64
    s1 += int.from_bytes(data[1*8 : 2*8], 'big')
    s1 &= MASK64
    s3 ^= s11
    s0 ^= s1
    s1 = spookyrot64(s1,32)
    s0 += s2
    s0 &= MASK64
    s2 += int.from_bytes(data[2*8 : 3*8], 'big')
    s4 ^= s0
    s1 ^= s2
    s2 = spookyrot64(s2,43)
    s1 += s3
    s1 &= MASK64
    s3 += int.from_bytes(data[3*8 : 4*8], 'big')
    s3 &= MASK64
    s5 ^= s1
    s2 ^= s3
    s3 = spookyrot64(s3,31)
    s2 += s4
    s2 &= MASK64
    s4 += int.from_bytes(data[4*8 : 5*8], 'big')
    s4 &= MASK64
    s6 ^= s2
    s3 ^= s4
    s4 = spookyrot64(s4,17)
    s3 += s5
    s3 &= MASK64
    s5 += int.from_bytes(data[5*8 : 6*8], 'big')
    s5 &= MASK64
    s7 ^= s3
    s4 ^= s5
    s5 = spookyrot64(s5,28)
    s4 += s6
    s4 &= MASK64
    s6 += int.from_bytes(data[6*8 : 7*8], 'big')
    s6 &= MASK64
    s8 ^= s4
    s5 ^= s6
    s6 = spookyrot64(s6,39)
    s5 += s7
    s5 &= MASK64
    s7 += int.from_bytes(data[7*8 : 8*8], 'big')
    s7 &= MASK64
    s9 ^= s5
    s6 ^= s7
    s7 = spookyrot64(s7,57)
    s6 += s8
    s6 &= MASK64
    s8 += int.from_bytes(data[8*8 : 9*8], 'big')
    s8 &= MASK64
    s10 ^= s6
    s7 ^= s8
    s8 = spookyrot64(s8,55)
    s7 += s9
    s7 &= MASK64
    s9 += int.from_bytes(data[9*8 : 10*8], 'big')
    s9 &= MASK64
    s11 ^= s7
    s8 ^= s9
    s9 = spookyrot64(s9,54)
    s8 += s10
    s8 &= MASK64
    s10 += int.from_bytes(data[10*8 : 11*8], 'big')
    s0 ^= s8
    s9 ^= s10
    s10 = spookyrot64(s10,22)
    s9 += s11
    s9 &= MASK64
    s11 += int.from_bytes(data[11*8 : 12*8], 'big')
    s11 &= MASK64
    s1 ^= s9
    s10 ^= s11
    s11 = spookyrot64(s11,46)
    s10 += s0
    s10 &= MASK64
    return s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11


#
# Mix all 12 inputs together so that h0, h1 are a hash of them all.
#
# For two inputs differing in just the input bits
# Where "differ" means xor or subtraction
# And the base value is random, or a counting value starting at that bit
# The final result will have each bit of h0, h1 flip
# For every input bit,
# with probability 50 +- .3%
# For every pair of input bits,
# with probability 50 +- 3%
#
# This does not rely on the last Mix() call having already mixed some.
# Two iterations was almost good enough for a 64-bit result, but a
# 128-bit result is reported, so End() does three iterations.
# 
def spookyendpartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11):
    h11 += h1
    h11 &= MASK64
    h2 ^= h11
    h1 = spookyrot64(h1,44)
    h0 += h2
    h0 &= MASK64
    h3 ^= h0
    h2 = spookyrot64(h2,15)
    h1 += h3
    h1 &= MASK64
    h4 ^= h1
    h3 = spookyrot64(h3,34)
    h2 += h4
    h2 &= MASK64
    h5 ^= h2
    h4 = spookyrot64(h4,21)
    h3 += h5
    h3 &= MASK64
    h6 ^= h3
    h5 = spookyrot64(h5,38)
    h4 += h6
    h4 &= MASK64
    h7 ^= h4
    h6 = spookyrot64(h6,33)
    h5 += h7
    h5 &= MASK64
    h8 ^= h5
    h7 = spookyrot64(h7,10)
    h6 += h8
    h6 &= MASK64
    h9 ^= h6
    h8 = spookyrot64(h8,13)
    h7 += h9
    h7 &= MASK64
    h10^= h7
    h9 = spookyrot64(h9,38)
    h8 += h10
    h8 &= MASK64
    h11^= h8
    h10= spookyrot64(h10,53)
    h9 += h11
    h9 &= MASK64
    h10 ^= h9
    h11= spookyrot64(h11,42)
    h10 += h0
    h10 &= MASK64
    h1 ^= h10
    h0 = spookyrot64(h0,54)
    return h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11
    
def spookyend(data, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11):
    h0 += data[0]
    h1 += data[1]
    h2 += data[2]
    h3 += data[3]
    h4 += data[4]
    h5 += data[5]
    h6 += data[6]
    h7 += data[7]
    h8 += data[8]
    h9 += data[9]
    h10 += data[10]
    h11 += data[11]
    h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11 = \
    spookyendpartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11)
    h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11 = \
    spookyendpartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11)
    h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11 = \
    spookyendpartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11)
    return h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11

#
# The goal is for each bit of the input to expand into 128 bits of 
#   apparent entropy before it is fully overwritten.
# n trials both set and cleared at least m bits of h0 h1 h2 h3
#   n: 2   m: 29
#   n: 3   m: 46
#   n: 4   m: 57
#   n: 5   m: 107
#   n: 6   m: 146
#   n: 7   m: 152
# when run forwards or backwards
# for all 1-bit and 2-bit diffs
# with diffs defined by either xor or subtraction
# with a base of all zeros plus a counter, or plus another bit, or random
#
def spookyshortmix(h0, h1, h2, h3):
    h2 = spookyrot64(h2,50)
    h2 += h3
    h2 &= MASK64
    h0 ^= h2
    h3 = spookyrot64(h3,52)
    h3 += h0
    h3 &= MASK64
    h1 ^= h3
    h0 = spookyrot64(h0,30)
    h0 += h1
    h0 &= MASK64
    h2 ^= h0
    h1 = spookyrot64(h1,41)
    h1 += h2
    h1 &= MASK64
    h3 ^= h1
    h2 = spookyrot64(h2,54)
    h2 += h3
    h2 &= MASK64
    h0 ^= h2
    h3 = spookyrot64(h3,48)
    h3 += h0
    h3 &= MASK64
    h1 ^= h3
    h0 = spookyrot64(h0,38)
    h0 += h1
    h0 &= MASK64
    h2 ^= h0
    h1 = spookyrot64(h1,37)
    h1 += h2
    h1 &= MASK64
    h3 ^= h1
    h2 = spookyrot64(h2,62)
    h2 += h3
    h2 &= MASK64
    h0 ^= h2
    h3 = spookyrot64(h3,34)
    h3 += h0
    h3 &= MASK64
    h1 ^= h3
    h0 = spookyrot64(h0,5)
    h0 += h1
    h0 &= MASK64
    h2 ^= h0
    h1 = spookyrot64(h1,36)
    h1 += h2
    h1 &= MASK64
    h3 ^= h1
    return h0, h1, h2, h3

#
# Mix all 4 inputs together so that h0, h1 are a hash of them all.
#
# For two inputs differing in just the input bits
# Where "differ" means xor or subtraction
# And the base value is random, or a counting value starting at that bit
# The final result will have each bit of h0, h1 flip
# For every input bit,
# with probability 50 +- .3% (it is probably better than that)
# For every pair of input bits,
# with probability 50 +- .75% (the worst case is approximately that)
#
def spookyshortend(h0, h1, h2, h3):
    h3 ^= h2
    h2 = spookyrot64(h2,15)
    h3 += h2
    h3 &= MASK64
    h0 ^= h3
    h3 = spookyrot64(h3,52)
    h0 += h3
    h0 &= MASK64
    h1 ^= h0
    h0 = spookyrot64(h0,26)
    h1 += h0
    h1 &= MASK64
    h2 ^= h1
    h1 = spookyrot64(h1,51)
    h2 += h1
    h2 &= MASK64
    h3 ^= h2
    h2 = spookyrot64(h2,28)
    h3 += h2
    h3 &= MASK64
    h0 ^= h3
    h3 = spookyrot64(h3,9)
    h0 += h3
    h0 &= MASK64
    h1 ^= h0
    h0 = spookyrot64(h0,47)
    h1 += h0
    h1 &= MASK64
    h2 ^= h1
    h1 = spookyrot64(h1,54)
    h2 += h1
    h2 &= MASK64
    h3 ^= h2
    h2 = spookyrot64(h2,32)
    h3 += h2
    h3 &= MASK64
    h0 ^= h3
    h3 = spookyrot64(h3,25)
    h0 += h3
    h0 &= MASK64
    h1 ^= h0
    h0 = spookyrot64(h0,63)
    h1 += h0
    h1 &= MASK64

MASK64 = 0xffffffffffffffff
MASK32 = 0xffffffff
class SpookyHash:
    """
    SpookyHash is a fast hash algorithm for hash table lookup.
    It produces 128-bit hash values.
    """

    def __init__(self, seed1, seed2):
        self.m_length = 0
        self.m_remainder = 0
        self.m_state = [8] * self.sc_numVars
        self.m_state[0] = [seed1]
        self.m_state[0] = [seed2]

    @classmethod
    def Short(cls,
            message: bytes,  # message (array of bytes, not necessarily aligned)
            hash1: int,    # in/out: in the seed, out the hash value
            hash2: int):   # in/out: in the seed, out the hash value
        buf = [0] * 2*cls.sc_numVars
        length = len(message)
        
        remainder = length%32
        a = hash1
        b = hash2
        c = cls.sc_const
        d = cls.sc_const

        if length > 15:
            end = (length/32)*4 * 4
            ip64 = 0
            
            # handle all complete sets of 32 bytes
            while ip64 < end:
                c += int.from_bytes(message[ip64 : ip64 + 1*8], 'big') & MASK64
                d += int.from_bytes(message[ip64 + 1*8 : ip64 + 2*8], 'big') & MASK64
                a,b,c,d = spookyshortmix(a,b,c,d)
                a += int.from_bytes(message[ip64 + 2*8 : ip64 + 3*8], 'big') & MASK64
                b += int.from_bytes(message[ip64 + 3*8 : ip64 + 4*8], 'big') & MASK64
                a,b,c,d = spookyshortmix(a,b,c,d)
                ip64 += 4*8
            
            # Handle the case of 16+ remaining bytes.
            if remainder >= 16:
                c += int.from_bytes(message[ip64 : ip64 + 1*8], 'big') & MASK64
                d += int.from_bytes(message[ip64 + 1*8 : ip64 + 2*8], 'big') & MASK64
                a,b,c,d = spookyshortmix(a,b,c,d)
                ip64 += 2*8
                remainder -= 16
        
        # Handle the last 0..15 bytes, and its length
        d += length << 56
        if remainder == 15:
            d += (int.from_bytes(message[ip64 + 14], 'big') << 48) & MASK64
        if remainder == 15 or remainder == 14:
            d += (int.from_bytes(message[ip64 + 13], 'big') << 40) & MASK64
        if remainder == 15 or remainder == 14 or remainder == 13:
            d += (int.from_bytes(message[ip64 + 12], 'big') << 32) & MASK64
        if remainder == 15 or remainder == 14 or remainder == 13 or remainder == 12:
            c += int.from_bytes(message[ip64 : ip64 + 1*8], 'big') & MASK64

        
        if remainder == 11:
            d += (int.from_bytes(message[ip64 + 10], 'big') << 16) & MASK64
        if remainder == 11 or remainder == 10:
            d += (int.from_bytes(message[ip64 + 9], 'big') << 8) & MASK64
        if remainder == 11 or remainder == 10 or remainder == 9:
            d += int.from_bytes(message[ip64 + 8], 'big') & MASK64
        if remainder == 11 or remainder == 10 or remainder == 9 or remainder == 8:
            c += int.from_bytes(message[ip64 : ip64 + 1*8], 'big') & MASK64
        
        if remainder == 7:
            c += (int.from_bytes(message[ip64 + 6], 'big') << 48) & MASK64
        if remainder == 7 or remainder == 6:
            c += (int.from_bytes(message[ip64 + 5], 'big') << 40) & MASK64
        if remainder == 7 or remainder == 6 or remainder == 5:
            c += (int.from_bytes(message[ip64 + 4], 'big') << 32) & MASK64
        if remainder == 7 or remainder == 6 or remainder == 5 or remainder == 4:
            c +=  int.from_bytes(message[ip64 : ip64 + 1*4], 'big')
        
        if remainder == 3:
            c += (int.from_bytes(message[ip64 + 2], 'big') << 16) & MASK64
        if remainder == 3 or remainder == 2:
            c += (int.from_bytes(message[ip64 + 1], 'big') << 8) & MASK64
        if remainder == 3 or remainder == 2 or remainder == 1:
            c += int.from_bytes(message[ip64 + 0], 'big') & MASK64

        if remainder == 0:
            c += cls.sc_const & MASK64
            d += cls.sc_const & MASK64
        a,b,c,d = spookyshortend(a,b,c,d)
        return a,b

    
    # do the whole hash in one call
    def Hash128(self, message, hash1, hash2):
        length = len(message)
        if length < self.sc_bufSize:
            return self.Short(message, length, hash1, hash2)

        buf = [0] * self.sc_numVars
        
        h0=h3=h6=h9  = hash1
        h1=h4=h7=h10 = hash2
        h2=h5=h8=h11 = self.sc_const
        
        end = (length/self.sc_blockSize)*self.sc_numVars * 4;
        ip64 = 0

        # handle all whole sc_blockSize blocks of bytes

        while ip64 < end:
            h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11 = \
            spookymix(message[ip64:], h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11)
            ip64 += self.sc_numVars


        # handle the last partial block of sc_blockSize bytes
        remainder = length - (end - ip64)
        buf = message[end : end+remainder]
        i = remainder
        while i < self.sc_blockSize - remainder:
            buf[i] = 0
            i += 1
        buf[self.sc_blockSize-1] = remainder
        
        # do some final mixing 
        h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11 = \
            spookyend(buf, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11);
        return h0, h1



    # number of uint64's in internal state
    sc_numVars = 12

    # size of the internal state
    sc_blockSize = sc_numVars*8

    # size of buffer of unhashed data, in bytes
    sc_bufSize = 2*sc_blockSize

    #
    # sc_const: a constant which:
    #  * is not zero
    #  * is odd
    #  * is a not-very-regular mix of 1's and 0's
    #  * does not need any other special mathematical properties
    #
    sc_const = 0xdeadbeefdeadbeef

    m_data = [0]  * 2*sc_numVars   # unhashed data, for partial messages
    m_state = [0] * sc_numVars  # internal state of the hash
    m_length = 0     # total length of the input so far
    m_remainder = 0  # length of unhashed data stashed in m_data
    


    # add a message fragment to the state
    def update(self, message):
        length = len(message)
        newLength = length + self.m_remainder
    
        # Is this message fragment too short?  If it is, stuff it away.
        if newLength < self.sc_bufSize:
            self.m_remainder = newLength
            self.m_data[self.m_remainder:] = message
            return self     # return self for daisy-chaining of calls
            
        # init the variables
        if self.m_length < self.sc_bufSize:
            self.m_state[0], self.m_state[1] = \
                self.Short(self.m_data, self.m_length, self.m_state[0], self.m_state[1])
            h0=h3=h6=h9  = int.from_bytes(self.m_state[0*8 : 1*8], 'big')
            h1=h4=h7=h10 = int.from_bytes(self.m_state[1*8 : 2*8], 'big')
            h2=h5=h8=h11 = self.sc_const
        else:
            h0 = int.from_bytes(self.m_state[0*8 : 1*8], 'big')
            h1 = int.from_bytes(self.m_state[1*8 : 2*8], 'big')
            h2 = int.from_bytes(self.m_state[2*8 : 3*8], 'big')
            h3 = int.from_bytes(self.m_state[3*8 : 4*8], 'big')
            h4 = int.from_bytes(self.m_state[4*8 : 5*8], 'big')
            h5 = int.from_bytes(self.m_state[5*8 : 6*8], 'big')
            h6 = int.from_bytes(self.m_state[6*8 : 7*8], 'big')
            h7 = int.from_bytes(self.m_state[7*8 : 8*8], 'big')
            h8 = int.from_bytes(self.m_state[8*8 : 9*8], 'big')
            h9 = int.from_bytes(self.m_state[9*8 : 10*8], 'big')
            h10 = int.from_bytes(self.m_state[10*8 : 11*8], 'big')
            h11 = int.from_bytes(self.m_state[11*8 : 12*8], 'big')
        self.m_length = length + self.m_length
    
        # if we've got anything stuffed away, use it now
        if self.m_remainder:
            prefix = self.sc_bufSize - self.m_remainder
            self.m_data[self.m_remainder:] = message[:prefix]
            h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11 = \
                spookymix(self.m_data, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11)
            h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11 = \
                spookymix(self.m_data[self.sc_numVars*8:], h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11)
            message = message[prefix:]
            length -= prefix
        else:
            prefix = 0
    
        # handle all whole blocks of sc_blockSize bytes
        end = (length/self.sc_blockSize)*self.sc_numVars * 4
        remainder = length-(end-prefix)
        ip64 = 0

        while ip64 < end:
            h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11 = \
                spookymix(message[ip64:], h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11)
        ip64 += self.sc_numVars * 8

        # stuff away the last few bytes
        self.m_remainder = remainder
        self.m_data[:remainder] = message[end:]
        
        # stuff away the variables
        self.m_state[0*8 : 1*8] = h0.to_bytes(8, 'big')
        self.m_state[1*8 : 2*8] = h1.to_bytes(8, 'big')
        self.m_state[2*8 : 3*8] = h2.to_bytes(8, 'big')
        self.m_state[3*8 : 4*8] = h3.to_bytes(8, 'big')
        self.m_state[4*8 : 5*8] = h4.to_bytes(8, 'big')
        self.m_state[5*8 : 6*8] = h5.to_bytes(8, 'big')
        self.m_state[6*8 : 7*8] = h6.to_bytes(8, 'big')
        self.m_state[7*8 : 8*8] = h7.to_bytes(8, 'big')
        self.m_state[8*8 : 9*8] = h8.to_bytes(8, 'big')
        self.m_state[9*8 : 10*8] = h9.to_bytes(8, 'big')
        self.m_state[10*8 : 11*8] = h10.to_bytes(8, 'big')
        self.m_state[11*8 : 12*8] = h11.to_bytes(8, 'big')

    
    #
    # Hash32: hash a single message in one call, produce 32-bit output
    #
    def Hash32(self, message, seed):
        hash1 = seed, hash2 = seed;
        hash1, hash2 = self.Hash128(message, hash1, hash2)
        return hash1 & MASK32


    # report the hash for the concatenation of all message fragments so far
    def Final(self):
        # init the variables
        if self.m_length < self.sc_bufSize:
            return self.Short( self.m_data, self.m_length, self.m_state[0], self.m_state[1]);
        
        data = self.m_data
        remainder = self.m_remainder
        
        h0 = int.from_bytes(self.m_state[0*8 : 1*8], 'big')
        h1 = int.from_bytes(self.m_state[1*8 : 2*8], 'big')
        h2 = int.from_bytes(self.m_state[2*8 : 3*8], 'big')
        h3 = int.from_bytes(self.m_state[3*8 : 4*8], 'big')
        h4 = int.from_bytes(self.m_state[4*8 : 5*8], 'big')
        h5 = int.from_bytes(self.m_state[5*8 : 6*8], 'big')
        h6 = int.from_bytes(self.m_state[6*8 : 7*8], 'big')
        h7 = int.from_bytes(self.m_state[7*8 : 8*8], 'big')
        h8 = int.from_bytes(self.m_state[8*8 : 9*8], 'big')
        h9 = int.from_bytes(self.m_state[9*8 : 10*8], 'big')
        h10 = int.from_bytes(self.m_state[10*8 : 11*8], 'big')
        h11 = int.from_bytes(self.m_state[11*8 : 12*8], 'big')

        if remainder >= self.sc_blockSize:
            # m_data can contain two blocks; handle any whole first block
            h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11 = \
                spookymix(data, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11)
            data += self.sc_numVars
            remainder -= self.sc_blockSize

        # mix in the last partial block, and the length mod sc_blockSize
        data[remainder:] = [0] * (self.sc_blockSize-remainder)
        data[self.sc_blockSize-1] = remainder
        
        # do some final mixing
        h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11 = \
            spookyend(data, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11)

        return h0, h1