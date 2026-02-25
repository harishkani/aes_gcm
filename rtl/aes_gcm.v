// =============================================================================
// aes_gcm.v  –  AES-128-GCM authenticated encryption (combinational)
//
// Supports a 96-bit IV, up to 1 block of AAD, and up to 1 block of plaintext.
// For multi-block use-cases the GHASH datapath would need to be extended.
//
// References: NIST SP 800-38D, RFC 5116
//
// Ports:
//   key        [127:0]  Cipher key (AES-128)
//   iv         [95:0]   Initialisation vector (96 bits)
//   aad        [127:0]  Additional authenticated data (1 block, left-aligned)
//   aad_valid          Set 1 when aad carries a full 128-bit AAD block
//   plaintext  [127:0]  Plaintext (1 block, left-aligned)
//   pt_valid           Set 1 when plaintext carries a 128-bit block
//   ciphertext [127:0]  Encrypted block (0 when pt_valid=0)
//   auth_tag   [127:0]  128-bit authentication tag
//
// GCM key/counter block layout:
//   J0  = IV[95:0] || 0x00000001
//   CTR1 = IV[95:0] || 0x00000002   (first counter block for encryption)
//
// GHASH length block:
//   {len(AAD) in bits [63:0], len(CT) in bits [63:0]}
//   = {64'd128 if aad_valid, 64'd128 if pt_valid}
// =============================================================================
module aes_gcm (
    input  [127:0] key,
    input  [95:0]  iv,
    // AAD (one 128-bit block)
    input  [127:0] aad,
    input          aad_valid,
    // Plaintext (one 128-bit block)
    input  [127:0] plaintext,
    input          pt_valid,
    // Outputs
    output [127:0] ciphertext,
    output [127:0] auth_tag
);

// ---------------------------------------------------------------------------
// Counter / key blocks
// ---------------------------------------------------------------------------
wire [127:0] J0   = {iv, 32'h00000001};
wire [127:0] CTR1 = {iv, 32'h00000002};

// ---------------------------------------------------------------------------
// AES sub-key H  (encrypt the all-zero block)
// ---------------------------------------------------------------------------
wire [127:0] H;
aes_encrypt u_H (
    .plaintext  (128'h0),
    .key        (key),
    .ciphertext (H)
);

// ---------------------------------------------------------------------------
// E_K(J0)  –  keystream block for tag generation
// ---------------------------------------------------------------------------
wire [127:0] EJ0;
aes_encrypt u_EJ0 (
    .plaintext  (J0),
    .key        (key),
    .ciphertext (EJ0)
);

// ---------------------------------------------------------------------------
// Counter block for plaintext encryption
// ---------------------------------------------------------------------------
wire [127:0] ECTR1;
aes_encrypt u_CTR1 (
    .plaintext  (CTR1),
    .key        (key),
    .ciphertext (ECTR1)
);

// Ciphertext = PT XOR E_K(CTR1)  (only valid when pt_valid=1)
assign ciphertext = pt_valid ? (plaintext ^ ECTR1) : 128'h0;

// ---------------------------------------------------------------------------
// GHASH  =  GHASH_H( A || 0* || C || 0* || [len(A)]_64 || [len(C)]_64 )
//
// State machine (unrolled, combinational):
//   S0 = 0
//   S1 = (S0  XOR A  ) * H     if aad_valid, else S0
//   S2 = (S1  XOR C  ) * H     if pt_valid,  else S1
//   S3 = (S2  XOR LEN) * H
//   tag = S3 XOR E_K(J0)
// ---------------------------------------------------------------------------

// ---- AAD step ----
wire [127:0] ghash_aad_in  = 128'h0 ^ aad;         // S0=0, XOR with AAD
wire [127:0] ghash_aad_out;
gf128_mult u_GHASH_AAD (
    .A (ghash_aad_in),
    .B (H),
    .Z (ghash_aad_out)
);
wire [127:0] S1 = aad_valid ? ghash_aad_out : 128'h0;

// ---- CT step ----
wire [127:0] ghash_ct_in  = S1 ^ ciphertext;
wire [127:0] ghash_ct_out;
gf128_mult u_GHASH_CT (
    .A (ghash_ct_in),
    .B (H),
    .Z (ghash_ct_out)
);
wire [127:0] S2 = pt_valid ? ghash_ct_out : S1;

// ---- Length block ----
wire [63:0] len_aad = aad_valid ? 64'd128 : 64'd0;
wire [63:0] len_ct  = pt_valid  ? 64'd128 : 64'd0;
wire [127:0] len_block = {len_aad, len_ct};

wire [127:0] ghash_len_in  = S2 ^ len_block;
wire [127:0] ghash_len_out;
gf128_mult u_GHASH_LEN (
    .A (ghash_len_in),
    .B (H),
    .Z (ghash_len_out)
);
wire [127:0] S3 = ghash_len_out;

// ---- Final tag ----
assign auth_tag = S3 ^ EJ0;

endmodule
