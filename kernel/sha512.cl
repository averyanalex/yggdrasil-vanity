// Rotate right function for 64-bit unsigned integers.
inline ulong sha512_rotr(ulong x, int n) { return (x >> n) | (x << (64 - n)); }

// Load big-endian 64-bit value from a 64-byte array.
inline ulong sha512_load_be(const __private uchar *base, size_t offset)
{
    return ((ulong)base[offset + 7]) | ((ulong)base[offset + 6] << 8) |
           ((ulong)base[offset + 5] << 16) | ((ulong)base[offset + 4] << 24) |
           ((ulong)base[offset + 3] << 32) | ((ulong)base[offset + 2] << 40) |
           ((ulong)base[offset + 1] << 48) | ((ulong)base[offset + 0] << 56);
}

// Load big-endian 64-bit value from a 128-byte array.
inline ulong sha512_load_be_128(const __private uchar *base, size_t offset)
{
    return ((ulong)base[offset + 7]) | ((ulong)base[offset + 6] << 8) |
           ((ulong)base[offset + 5] << 16) | ((ulong)base[offset + 4] << 24) |
           ((ulong)base[offset + 3] << 32) | ((ulong)base[offset + 2] << 40) |
           ((ulong)base[offset + 1] << 48) | ((ulong)base[offset + 0] << 56);
}

// Store big-endian 64-bit value to a 64-byte array.
inline void sha512_store_be(__private uchar *base, size_t offset, ulong x)
{
    base[offset + 7] = (uchar)(x & 0xFFUL);
    base[offset + 6] = (uchar)((x >> 8) & 0xFFUL);
    base[offset + 5] = (uchar)((x >> 16) & 0xFFUL);
    base[offset + 4] = (uchar)((x >> 24) & 0xFFUL);
    base[offset + 3] = (uchar)((x >> 32) & 0xFFUL);
    base[offset + 2] = (uchar)((x >> 40) & 0xFFUL);
    base[offset + 1] = (uchar)((x >> 48) & 0xFFUL);
    base[offset + 0] = (uchar)((x >> 56) & 0xFFUL);
}

// The 80 SHA512 round constants.
constant ulong SHA512_ROUND_CONSTANTS[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL,
    0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL, 0x59f111f1b605d019UL,
    0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL,
    0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
    0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL,
    0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL, 0x2de92c6f592b0275UL,
    0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL,
    0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
    0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL,
    0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL,
    0x92722c851482353bUL, 0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL,
    0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL,
    0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL,
    0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL,
    0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL,
    0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL,
    0xc67178f2e372532bUL, 0xca273eceea26619cUL, 0xd186b8c721c0c207UL,
    0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL,
    0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
    0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL,
    0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL};

// The SHA512 state structure.
typedef struct
{
    ulong st[8];
} sha512_State;

// Initialize a SHA512 state with IV.
inline sha512_State sha512_State_new()
{
    sha512_State state;
    // IV is defined as 64 bytes
    const __private uchar IV[64] = {
        0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae,
        0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
        0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51,
        0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c,
        0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
        0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79};

    for (int i = 0; i < 8; i++)
    {
        state.st[i] = sha512_load_be(IV, i * 8);
    }
    return state;
}

// Store the SHA512 state into a 64-byte output array.
inline void sha512_State_store(const sha512_State *state,
                               __private uchar *out)
{
    for (int i = 0; i < 8; i++)
    {
        sha512_store_be(out, i * 8, state->st[i]);
    }
}

// Add two SHA512 states.
inline void sha512_State_add(sha512_State *self, const sha512_State *other)
{
    for (int i = 0; i < 8; i++)
    {
        self->st[i] += other->st[i];
    }
}

// The W structure for the message schedule.
typedef struct
{
    ulong w[16];
} sha512_W;

// Initialize W struct from a 128-byte input block.
inline sha512_W sha512_W_new(const __private uchar *input)
{
    sha512_W w_struct;
    for (int i = 0; i < 16; i++)
    {
        w_struct.w[i] = sha512_load_be_128(input, i * 8);
    }
    return w_struct;
}

// Functions corresponding to SHA512 bitwise functions.
inline ulong sha512_big_ch(ulong x, ulong y, ulong z)
{
    return (x & y) ^ ((~x) & z);
}

inline ulong sha512_big_maj(ulong x, ulong y, ulong z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline ulong sha512_big_sigma0(ulong x)
{
    return sha512_rotr(x, 28) ^ sha512_rotr(x, 34) ^ sha512_rotr(x, 39);
}

inline ulong sha512_big_sigma1(ulong x)
{
    return sha512_rotr(x, 14) ^ sha512_rotr(x, 18) ^ sha512_rotr(x, 41);
}

inline ulong sha512_sigma0(ulong x)
{
    return sha512_rotr(x, 1) ^ sha512_rotr(x, 8) ^ (x >> 7);
}

inline ulong sha512_sigma1(ulong x)
{
    return sha512_rotr(x, 19) ^ sha512_rotr(x, 61) ^ (x >> 6);
}

// Performs a single update on W.
inline void sha512_W_big_m(sha512_W *w, int a, int b, int c, int d)
{
    w->w[a] = w->w[a] + sha512_sigma1(w->w[b]) + w->w[c] + sha512_sigma0(w->w[d]);
}

// Expand the message schedule.
inline void sha512_W_expand(sha512_W *w)
{
    for (int i = 0; i < 16; i++)
    {
        sha512_W_big_m(w, i, (i + 14) & 15, (i + 9) & 15, (i + 1) & 15);
    }
}

// Update the state with one round (big_f).
inline void sha512_W_big_f(sha512_W *w, sha512_State *state, int i, ulong k)
{
    // The indices are calculated modulo 8 as in the original code.
    int idx7 = (16 - i + 7) & 7;
    int idx4 = (16 - i + 4) & 7;
    int idx5 = (16 - i + 5) & 7;
    int idx6 = (16 - i + 6) & 7;
    int idx3 = (16 - i + 3) & 7;
    int idx0 = (16 - i + 0) & 7;
    int idx1 = (16 - i + 1) & 7;
    int idx2 = (16 - i + 2) & 7;

    state->st[idx7] =
        state->st[idx7] + sha512_big_sigma1(state->st[idx4]) +
        sha512_big_ch(state->st[idx4], state->st[idx5], state->st[idx6]) + k +
        w->w[i];
    state->st[idx3] = state->st[idx3] + state->st[idx7];
    state->st[idx7] =
        state->st[idx7] + sha512_big_sigma0(state->st[idx0]) +
        sha512_big_maj(state->st[idx0], state->st[idx1], state->st[idx2]);
}

// Process 16 rounds over the state using W.
inline void sha512_W_big_g(sha512_W *w, sha512_State *state, int s)
{
    // Each s processes 16 rounds
    for (int i = 0; i < 16; i++)
    {
        sha512_W_big_f(w, state, i, SHA512_ROUND_CONSTANTS[s * 16 + i]);
    }
}

// Process a full 128-byte message block.
inline void sha512_State_blocks(__private sha512_State *state,
                                const __private uchar *input)
{
    sha512_State t = *state;
    sha512_W w = sha512_W_new(input);

    for (int s = 0; s < 4; s++)
    {
        sha512_W_big_g(&w, &t, s);
        sha512_W_expand(&w);
    }

    // One final group of 16 rounds without expanding
    sha512_W_big_g(&w, &t, 4);
    sha512_State_add(&t, state);
    *state = t;
}

// The main hash function.
// input: pointer to 32 bytes (in private address space)
// out: pointer to 64 bytes (in private address space) where the digest will be
// stored.
void sha512_hash(const __private uchar *input, __private uchar *out)
{
    // Initialize state.
    sha512_State state = sha512_State_new();

    // Prepare a 128-byte padded block.
    __private uchar padded[128] = {0};
    for (int i = 0; i < 32; i++)
    {
        padded[i] = input[i];
    }
    padded[32] = 0x80; // append the '1' bit.

    // Append the length: in SHA512 the length in bits is stored in the last 8
    // bytes. For a 32-byte message, the bit-length is 256.
    ulong bits = 32 * 8;
    for (int i = 0; i < 8; i++)
    {
        padded[128 - 8 + i] = (uchar)((bits >> (56 - i * 8)) & 0xFFUL);
    }

    // Process the (single) block.
    sha512_State_blocks(&state, padded);

    // Store the final state into out.
    sha512_State_store(&state, out);
}
