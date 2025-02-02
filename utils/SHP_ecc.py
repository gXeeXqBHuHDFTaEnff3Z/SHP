
#!/usr/bin/env python3

from functools import lru_cache # for the hash cache

# supported ecc:
# 1. none: no error correction
# 2. hamming: hamming code without parity bit
# 3. hamming+: hamming code with parity bit
# 4. inline-hamming+: hamming code with parity bit as part of the message bitstream, but not per match. ecc is calculated and checked per message chunk.

@lru_cache(maxsize=65536) # cache frequent checksums
def check_checksum(ecc, message_bits, checksum_should_bits, message_chunk, chunksize):
    if (ecc == 'none'):
        raise ValueError(f"Can not compare checksums for ecc={ecc}.")
    elif (ecc == 'hamming'):
        # hamming code, no parity bit
        match, checksum_is_bits = check_hamming_checksum(message_bits, False, checksum_should_bits)
    elif (ecc == 'hamming+'):
        # hamming code, parity bit
        match, checksum_is_bits = check_hamming_checksum(message_bits, True, checksum_should_bits)
    elif (ecc == 'inline-hamming+'):
        # checksum is part of the message chunk. we only check it if the full chunk has been transmitted.
        if len(message_chunk) >= chunksize:
            message_bits, checksum_should_bits = extract_hamming_checksum(message_chunk)
            match, checksum_is_bits = check_hamming_checksum(message_bits, True, checksum_should_bits)
        else: 
            return True, '', ''
    
    return match, message_bits, checksum_is_bits

def compute_hamming_checksum(message_bits, overall_parity_bit_enabled):
    """
    Generate the Hamming code for the given message bits.

    :param message_bits: A string of bits ('0' and '1')
    :return: A string representing the Hamming code
    """
    n = len(message_bits)
    r = 0
    
    # Determine the number of parity bits needed
    while (1 << r) < (n + r + 1):
        r += 1

    # Initialize the list with None to include the parity positions
    code_length = n + r
    code = [None] * code_length
    
    # Place the data bits
    j = 0
    for i in range(1, code_length + 1):
        if (i & (i - 1)) == 0:  # Check if i is a power of 2
            continue
        code[i - 1] = int(message_bits[j])
        j += 1
          
    # Calculate the parity bits and place them in the code
    for i in range(r):
        parity_pos = (1 << i)
        parity = 0
        for j in range(1, code_length + 1):
            if j & parity_pos:  # Check if the parity position bit is 1
                if code[j - 1] is not None:
                    parity ^= code[j - 1]
        code[parity_pos - 1] = parity
        
    # Calculate the overall parity bit if needed
    if (overall_parity_bit_enabled):
        overall_parity = 0
        for bit in code:
            if bit is not None:
                overall_parity ^= bit
    
        # Append the overall parity bit to the code
        code.append(overall_parity)
    
    return ''.join(str(bit) for bit in code if bit is not None)


def compute_bch_checksum(message_bits):
    # Using PyCryptodome BCH (we assume it's already installed and configured)
    checksum_length = 256
    from Cryptodome.PublicKey import ECC
    bch = ECC.construct(curve='P-256', d=int(message_bits, 2))
    public_key = bch.pointQ
    return public_key.xy[0].to_bytes(checksum_length, 'big').hex()

def compute_reed_solomon_checksum(message_bits):
    checksum_length = 256
    from reedsolo import RSCodec # for computing BCH checksum
    rs = RSCodec(checksum_length)
    data = bytes(int(message_bits[i:i+8], 2) for i in range(0, len(message_bits), 8))
    encoded = rs.encode(data)
    return ''.join(format(x, '08b') for x in encoded[-checksum_length:])

@lru_cache(maxsize=65536) # cache frequent checksums
def checksum(message_bits, algorithm):
    if not message_bits or not isinstance(message_bits, str) or any(c not in '01' for c in message_bits):
        raise ValueError(f"Invalid message_bits {message_bits}: must be a non-empty string of binary digits.")
    if algorithm not in ["hamming", "hamming+", "bose-chaudhuri-hocquenghem", "reed-solomon"]:
        raise ValueError(f"Unsupported algorithm {algorithm} specified.")

    if algorithm == "hamming": # hamming, no parity bit
        return compute_hamming_checksum(message_bits, False)
    elif algorithm == "hamming+": # hamming, with parity bit
        return compute_hamming_checksum(message_bits, True)
    elif algorithm == "bose-chaudhuri-hocquenghem":
        return compute_bch_checksum(message_bits)
    elif algorithm == "reed-solomon":
        return compute_reed_solomon_checksum(message_bits)
        
def check_hamming_checksum(message_bits, overall_parity_bit_enabled, checksum):
    """
    Check if the given checksum matches the Hamming checksum for the message bits.

    :param message_bits: A string of bits ('0' and '1')
    :param overall_parity_bit_enabled: Boolean indicating if overall parity bit is used
    :param checksum: A string representing the provided checksum
    :return: Boolean indicating if the checksum matches
    """
    # Compute the checksum using the provided message bits
    computed_checksum = compute_hamming_checksum(message_bits, overall_parity_bit_enabled)
    
    # Compare the computed checksum with the provided checksum
    return computed_checksum == checksum, computed_checksum
    
def extract_hamming_checksum(hamming_code):
    """
    Extract the Hamming checksum and message bits from the combined hamming code.

    :param hamming_code: A string representing the combined Hamming code
    :return: A tuple (message_bits, checksum) where both are strings
    """
    code_length = len(hamming_code)
    r = 0
    
    # Determine the number of parity bits
    while (1 << r) < code_length:
        r += 1
    
    # Identify parity positions
    parity_positions = [1 << i for i in range(r)]
    
    # Extract the message bits
    message_bits = []
    for i in range(1, code_length + 1):
        if i not in parity_positions:
            message_bits.append(hamming_code[i - 1])
    
    # Extract the checksum (parity bits)
    checksum = []
    for pos in parity_positions:
        if pos <= code_length:
            checksum.append(hamming_code[pos - 1])
    
    # Check if there's an overall parity bit
    if len(hamming_code) > code_length:
        checksum.append(hamming_code[-1])
    
    #return message_bits, checksum
    return "".join(message_bits), "".join(checksum)
    
def compute_checksum_6bit(bitstring: str) -> str:
    """
    Calculate a checksum with fixed 6-bit length for a binary string.
    Used for experiment error detection in the SHPonline variant.
    
    Args:
        bitstring (str): A string of '0's and '1's between 2 and 64 bits in length
        
    Returns:
        str: A 6-bit checksum as a string of '0's and '1's
        
    Raises:
        ValueError: If input length is not between 2 and 64 bits or contains invalid characters
    """
    # Validate input length
    if not 2 <= len(bitstring) <= 64:
        raise ValueError("Bitstring length must be between 2 and 64 bits")
    
    # Validate input characters
    if not all(bit in '01' for bit in bitstring):
        raise ValueError("Bitstring must contain only '0' and '1' characters")
    
    # Convert bitstring to integer
    value = int(bitstring, 2)
    
    # Calculate checksum using XOR folding
    # First split the number into 6-bit chunks
    chunks = []
    temp_value = value
    while temp_value > 0:
        chunks.append(temp_value & 0b111111)  # Get last 6 bits
        temp_value >>= 6  # Shift right by 6 bits
    
    # If no chunks (all zeros), add one chunk of zeros
    if not chunks:
        chunks.append(0)
    
    # XOR all chunks together
    checksum = chunks[0]
    for chunk in chunks[1:]:
        checksum ^= chunk
    
    # Convert to 6-bit binary string
    return format(checksum, '06b')

def get_checksum_length(ecc, bitlength):
    """calculates number of bits for the checksum given the data bitlength"""
    if (ecc == 'none'):
        checksum_length = 0
    elif (ecc == 'hamming') or (ecc == 'hamming+'):
        # Determine the number of ecc bits needed
        n = bitlength
        r = 0
        
        while (1 << r) < (n + r + 1):
            r += 1
            
        # extra parity bit
        if (ecc == 'hamming+'):
            r = r + 1
        
        checksum_length = r
    elif (ecc == 'inline-hamming+'):
        checksum_length = 0 # no additional bits needed per matching chunk
    else:
        raise ValueError(f"Unsupported ECC code: {ecc}") 

    return checksum_length
