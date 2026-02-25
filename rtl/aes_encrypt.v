// =============================================================================
// aes_encrypt.v  –  Combinational AES-128 encryption
//
// Interface
//   plaintext  [127:0]  – input block
//   key        [127:0]  – 128-bit cipher key
//   ciphertext [127:0]  – encrypted output block
//
// All 10 rounds + key-schedule are unrolled combinationally.
// State byte mapping (big-endian, column-major, as per FIPS-197):
//   byte 0 = bits[127:120] = s[row0][col0]
//   byte 1 = bits[119:112] = s[row1][col0]  ...
// =============================================================================
module aes_encrypt (
    input  [127:0] plaintext,
    input  [127:0] key,
    output reg [127:0] ciphertext
);

// ---------------------------------------------------------------------------
// S-Box (forward, FIPS-197 Figure 7)
// ---------------------------------------------------------------------------
function [7:0] sbox_f;
    input [7:0] x;
    case (x)
        8'h00:sbox_f=8'h63; 8'h01:sbox_f=8'h7c; 8'h02:sbox_f=8'h77; 8'h03:sbox_f=8'h7b;
        8'h04:sbox_f=8'hf2; 8'h05:sbox_f=8'h6b; 8'h06:sbox_f=8'h6f; 8'h07:sbox_f=8'hc5;
        8'h08:sbox_f=8'h30; 8'h09:sbox_f=8'h01; 8'h0a:sbox_f=8'h67; 8'h0b:sbox_f=8'h2b;
        8'h0c:sbox_f=8'hfe; 8'h0d:sbox_f=8'hd7; 8'h0e:sbox_f=8'hab; 8'h0f:sbox_f=8'h76;
        8'h10:sbox_f=8'hca; 8'h11:sbox_f=8'h82; 8'h12:sbox_f=8'hc9; 8'h13:sbox_f=8'h7d;
        8'h14:sbox_f=8'hfa; 8'h15:sbox_f=8'h59; 8'h16:sbox_f=8'h47; 8'h17:sbox_f=8'hf0;
        8'h18:sbox_f=8'had; 8'h19:sbox_f=8'hd4; 8'h1a:sbox_f=8'ha2; 8'h1b:sbox_f=8'haf;
        8'h1c:sbox_f=8'h9c; 8'h1d:sbox_f=8'ha4; 8'h1e:sbox_f=8'h72; 8'h1f:sbox_f=8'hc0;
        8'h20:sbox_f=8'hb7; 8'h21:sbox_f=8'hfd; 8'h22:sbox_f=8'h93; 8'h23:sbox_f=8'h26;
        8'h24:sbox_f=8'h36; 8'h25:sbox_f=8'h3f; 8'h26:sbox_f=8'hf7; 8'h27:sbox_f=8'hcc;
        8'h28:sbox_f=8'h34; 8'h29:sbox_f=8'ha5; 8'h2a:sbox_f=8'he5; 8'h2b:sbox_f=8'hf1;
        8'h2c:sbox_f=8'h71; 8'h2d:sbox_f=8'hd8; 8'h2e:sbox_f=8'h31; 8'h2f:sbox_f=8'h15;
        8'h30:sbox_f=8'h04; 8'h31:sbox_f=8'hc7; 8'h32:sbox_f=8'h23; 8'h33:sbox_f=8'hc3;
        8'h34:sbox_f=8'h18; 8'h35:sbox_f=8'h96; 8'h36:sbox_f=8'h05; 8'h37:sbox_f=8'h9a;
        8'h38:sbox_f=8'h07; 8'h39:sbox_f=8'h12; 8'h3a:sbox_f=8'h80; 8'h3b:sbox_f=8'he2;
        8'h3c:sbox_f=8'heb; 8'h3d:sbox_f=8'h27; 8'h3e:sbox_f=8'hb2; 8'h3f:sbox_f=8'h75;
        8'h40:sbox_f=8'h09; 8'h41:sbox_f=8'h83; 8'h42:sbox_f=8'h2c; 8'h43:sbox_f=8'h1a;
        8'h44:sbox_f=8'h1b; 8'h45:sbox_f=8'h6e; 8'h46:sbox_f=8'h5a; 8'h47:sbox_f=8'ha0;
        8'h48:sbox_f=8'h52; 8'h49:sbox_f=8'h3b; 8'h4a:sbox_f=8'hd6; 8'h4b:sbox_f=8'hb3;
        8'h4c:sbox_f=8'h29; 8'h4d:sbox_f=8'he3; 8'h4e:sbox_f=8'h2f; 8'h4f:sbox_f=8'h84;
        8'h50:sbox_f=8'h53; 8'h51:sbox_f=8'hd1; 8'h52:sbox_f=8'h00; 8'h53:sbox_f=8'hed;
        8'h54:sbox_f=8'h20; 8'h55:sbox_f=8'hfc; 8'h56:sbox_f=8'hb1; 8'h57:sbox_f=8'h5b;
        8'h58:sbox_f=8'h6a; 8'h59:sbox_f=8'hcb; 8'h5a:sbox_f=8'hbe; 8'h5b:sbox_f=8'h39;
        8'h5c:sbox_f=8'h4a; 8'h5d:sbox_f=8'h4c; 8'h5e:sbox_f=8'h58; 8'h5f:sbox_f=8'hcf;
        8'h60:sbox_f=8'hd0; 8'h61:sbox_f=8'hef; 8'h62:sbox_f=8'haa; 8'h63:sbox_f=8'hfb;
        8'h64:sbox_f=8'h43; 8'h65:sbox_f=8'h4d; 8'h66:sbox_f=8'h33; 8'h67:sbox_f=8'h85;
        8'h68:sbox_f=8'h45; 8'h69:sbox_f=8'hf9; 8'h6a:sbox_f=8'h02; 8'h6b:sbox_f=8'h7f;
        8'h6c:sbox_f=8'h50; 8'h6d:sbox_f=8'h3c; 8'h6e:sbox_f=8'h9f; 8'h6f:sbox_f=8'ha8;
        8'h70:sbox_f=8'h51; 8'h71:sbox_f=8'ha3; 8'h72:sbox_f=8'h40; 8'h73:sbox_f=8'h8f;
        8'h74:sbox_f=8'h92; 8'h75:sbox_f=8'h9d; 8'h76:sbox_f=8'h38; 8'h77:sbox_f=8'hf5;
        8'h78:sbox_f=8'hbc; 8'h79:sbox_f=8'hb6; 8'h7a:sbox_f=8'hda; 8'h7b:sbox_f=8'h21;
        8'h7c:sbox_f=8'h10; 8'h7d:sbox_f=8'hff; 8'h7e:sbox_f=8'hf3; 8'h7f:sbox_f=8'hd2;
        8'h80:sbox_f=8'hcd; 8'h81:sbox_f=8'h0c; 8'h82:sbox_f=8'h13; 8'h83:sbox_f=8'hec;
        8'h84:sbox_f=8'h5f; 8'h85:sbox_f=8'h97; 8'h86:sbox_f=8'h44; 8'h87:sbox_f=8'h17;
        8'h88:sbox_f=8'hc4; 8'h89:sbox_f=8'ha7; 8'h8a:sbox_f=8'h7e; 8'h8b:sbox_f=8'h3d;
        8'h8c:sbox_f=8'h64; 8'h8d:sbox_f=8'h5d; 8'h8e:sbox_f=8'h19; 8'h8f:sbox_f=8'h73;
        8'h90:sbox_f=8'h60; 8'h91:sbox_f=8'h81; 8'h92:sbox_f=8'h4f; 8'h93:sbox_f=8'hdc;
        8'h94:sbox_f=8'h22; 8'h95:sbox_f=8'h2a; 8'h96:sbox_f=8'h90; 8'h97:sbox_f=8'h88;
        8'h98:sbox_f=8'h46; 8'h99:sbox_f=8'hee; 8'h9a:sbox_f=8'hb8; 8'h9b:sbox_f=8'h14;
        8'h9c:sbox_f=8'hde; 8'h9d:sbox_f=8'h5e; 8'h9e:sbox_f=8'h0b; 8'h9f:sbox_f=8'hdb;
        8'ha0:sbox_f=8'he0; 8'ha1:sbox_f=8'h32; 8'ha2:sbox_f=8'h3a; 8'ha3:sbox_f=8'h0a;
        8'ha4:sbox_f=8'h49; 8'ha5:sbox_f=8'h06; 8'ha6:sbox_f=8'h24; 8'ha7:sbox_f=8'h5c;
        8'ha8:sbox_f=8'hc2; 8'ha9:sbox_f=8'hd3; 8'haa:sbox_f=8'hac; 8'hab:sbox_f=8'h62;
        8'hac:sbox_f=8'h91; 8'had:sbox_f=8'h95; 8'hae:sbox_f=8'he4; 8'haf:sbox_f=8'h79;
        8'hb0:sbox_f=8'he7; 8'hb1:sbox_f=8'hc8; 8'hb2:sbox_f=8'h37; 8'hb3:sbox_f=8'h6d;
        8'hb4:sbox_f=8'h8d; 8'hb5:sbox_f=8'hd5; 8'hb6:sbox_f=8'h4e; 8'hb7:sbox_f=8'ha9;
        8'hb8:sbox_f=8'h6c; 8'hb9:sbox_f=8'h56; 8'hba:sbox_f=8'hf4; 8'hbb:sbox_f=8'hea;
        8'hbc:sbox_f=8'h65; 8'hbd:sbox_f=8'h7a; 8'hbe:sbox_f=8'hae; 8'hbf:sbox_f=8'h08;
        8'hc0:sbox_f=8'hba; 8'hc1:sbox_f=8'h78; 8'hc2:sbox_f=8'h25; 8'hc3:sbox_f=8'h2e;
        8'hc4:sbox_f=8'h1c; 8'hc5:sbox_f=8'ha6; 8'hc6:sbox_f=8'hb4; 8'hc7:sbox_f=8'hc6;
        8'hc8:sbox_f=8'he8; 8'hc9:sbox_f=8'hdd; 8'hca:sbox_f=8'h74; 8'hcb:sbox_f=8'h1f;
        8'hcc:sbox_f=8'h4b; 8'hcd:sbox_f=8'hbd; 8'hce:sbox_f=8'h8b; 8'hcf:sbox_f=8'h8a;
        8'hd0:sbox_f=8'h70; 8'hd1:sbox_f=8'h3e; 8'hd2:sbox_f=8'hb5; 8'hd3:sbox_f=8'h66;
        8'hd4:sbox_f=8'h48; 8'hd5:sbox_f=8'h03; 8'hd6:sbox_f=8'hf6; 8'hd7:sbox_f=8'h0e;
        8'hd8:sbox_f=8'h61; 8'hd9:sbox_f=8'h35; 8'hda:sbox_f=8'h57; 8'hdb:sbox_f=8'hb9;
        8'hdc:sbox_f=8'h86; 8'hdd:sbox_f=8'hc1; 8'hde:sbox_f=8'h1d; 8'hdf:sbox_f=8'h9e;
        8'he0:sbox_f=8'he1; 8'he1:sbox_f=8'hf8; 8'he2:sbox_f=8'h98; 8'he3:sbox_f=8'h11;
        8'he4:sbox_f=8'h69; 8'he5:sbox_f=8'hd9; 8'he6:sbox_f=8'h8e; 8'he7:sbox_f=8'h94;
        8'he8:sbox_f=8'h9b; 8'he9:sbox_f=8'h1e; 8'hea:sbox_f=8'h87; 8'heb:sbox_f=8'he9;
        8'hec:sbox_f=8'hce; 8'hed:sbox_f=8'h55; 8'hee:sbox_f=8'h28; 8'hef:sbox_f=8'hdf;
        8'hf0:sbox_f=8'h8c; 8'hf1:sbox_f=8'ha1; 8'hf2:sbox_f=8'h89; 8'hf3:sbox_f=8'h0d;
        8'hf4:sbox_f=8'hbf; 8'hf5:sbox_f=8'he6; 8'hf6:sbox_f=8'h42; 8'hf7:sbox_f=8'h68;
        8'hf8:sbox_f=8'h41; 8'hf9:sbox_f=8'h99; 8'hfa:sbox_f=8'h2d; 8'hfb:sbox_f=8'h0f;
        8'hfc:sbox_f=8'hb0; 8'hfd:sbox_f=8'h54; 8'hfe:sbox_f=8'hbb; 8'hff:sbox_f=8'h16;
    endcase
endfunction

// ---------------------------------------------------------------------------
// GF(2^8) multiply-by-2  (xtime)
// ---------------------------------------------------------------------------
function [7:0] xtime_f;
    input [7:0] x;
    xtime_f = x[7] ? ((x << 1) ^ 8'h1b) : (x << 1);
endfunction

// ---------------------------------------------------------------------------
// GF(2^8) multiply-by-3  (xtime XOR identity)
// ---------------------------------------------------------------------------
function [7:0] xtimes3_f;
    input [7:0] x;
    xtimes3_f = xtime_f(x) ^ x;
endfunction

// ---------------------------------------------------------------------------
// SubWord: S-Box on each byte of a 32-bit word
// ---------------------------------------------------------------------------
function [31:0] sub_word_f;
    input [31:0] w;
    sub_word_f = { sbox_f(w[31:24]), sbox_f(w[23:16]),
                   sbox_f(w[15:8]),  sbox_f(w[7:0]) };
endfunction

// ---------------------------------------------------------------------------
// RotWord: rotate left by 8 bits
// ---------------------------------------------------------------------------
function [31:0] rot_word_f;
    input [31:0] w;
    rot_word_f = { w[23:0], w[31:24] };
endfunction

// ---------------------------------------------------------------------------
// Round Constant for key schedule (RCON[1..10])
// ---------------------------------------------------------------------------
function [7:0] rcon_f;
    input [4:0] r;      // round index 1..10
    case (r)
        5'd1 : rcon_f = 8'h01;
        5'd2 : rcon_f = 8'h02;
        5'd3 : rcon_f = 8'h04;
        5'd4 : rcon_f = 8'h08;
        5'd5 : rcon_f = 8'h10;
        5'd6 : rcon_f = 8'h20;
        5'd7 : rcon_f = 8'h40;
        5'd8 : rcon_f = 8'h80;
        5'd9 : rcon_f = 8'h1b;
        5'd10: rcon_f = 8'h36;
        default: rcon_f = 8'h00;
    endcase
endfunction

// ---------------------------------------------------------------------------
// SubBytes: apply S-Box to all 16 bytes of the 128-bit state
// ---------------------------------------------------------------------------
function [127:0] sub_bytes_f;
    input [127:0] s;
    reg [127:0] tmp;
    integer bi;
    begin
        tmp = 128'h0;
        for (bi = 0; bi < 16; bi = bi + 1)
            tmp[8*(15-bi) +: 8] = sbox_f(s[8*(15-bi) +: 8]);
        sub_bytes_f = tmp;
    end
endfunction

// ---------------------------------------------------------------------------
// ShiftRows (FIPS-197 §5.1.2)
//   Row 0: no shift   (bytes  0, 4, 8,12)
//   Row 1: left by 1  (bytes  1, 5, 9,13)
//   Row 2: left by 2  (bytes  2, 6,10,14)
//   Row 3: left by 3  (bytes  3, 7,11,15)
// ---------------------------------------------------------------------------
function [127:0] shift_rows_f;
    input [127:0] s;
    reg [127:0] r;
    begin
        // Row 0 – unchanged
        r[127:120] = s[127:120];   // byte 0  -> 0
        r[95:88]   = s[95:88];     // byte 4  -> 4
        r[63:56]   = s[63:56];     // byte 8  -> 8
        r[31:24]   = s[31:24];     // byte 12 -> 12
        // Row 1 – rotate left 1
        r[119:112] = s[87:80];     // byte 5  -> pos 1
        r[87:80]   = s[55:48];     // byte 9  -> pos 5
        r[55:48]   = s[23:16];     // byte 13 -> pos 9
        r[23:16]   = s[119:112];   // byte 1  -> pos 13
        // Row 2 – rotate left 2
        r[111:104] = s[47:40];     // byte 10 -> pos 2
        r[79:72]   = s[15:8];      // byte 14 -> pos 6
        r[47:40]   = s[111:104];   // byte 2  -> pos 10
        r[15:8]    = s[79:72];     // byte 6  -> pos 14
        // Row 3 – rotate left 3
        r[103:96]  = s[7:0];       // byte 15 -> pos 3
        r[71:64]   = s[103:96];    // byte 3  -> pos 7
        r[39:32]   = s[71:64];     // byte 7  -> pos 11
        r[7:0]     = s[39:32];     // byte 11 -> pos 15
        shift_rows_f = r;
    end
endfunction

// ---------------------------------------------------------------------------
// MixColumns: one column [a,b,c,d] → new column
// ---------------------------------------------------------------------------
function [31:0] mix_col_f;
    input [31:0] col;
    reg [7:0] a, b, c, d;
    begin
        a = col[31:24];
        b = col[23:16];
        c = col[15:8];
        d = col[7:0];
        mix_col_f[31:24] = xtime_f(a)  ^ xtimes3_f(b) ^ c           ^ d;
        mix_col_f[23:16] = a           ^ xtime_f(b)   ^ xtimes3_f(c) ^ d;
        mix_col_f[15:8]  = a           ^ b             ^ xtime_f(c)   ^ xtimes3_f(d);
        mix_col_f[7:0]   = xtimes3_f(a) ^ b            ^ c            ^ xtime_f(d);
    end
endfunction

// ---------------------------------------------------------------------------
// MixColumns applied to all 4 columns
// ---------------------------------------------------------------------------
function [127:0] mix_columns_f;
    input [127:0] s;
    mix_columns_f = { mix_col_f(s[127:96]),
                      mix_col_f(s[95:64]),
                      mix_col_f(s[63:32]),
                      mix_col_f(s[31:0]) };
endfunction

// ---------------------------------------------------------------------------
// Module-level storage for key schedule words
// ---------------------------------------------------------------------------
reg [31:0] w [0:43];
integer    i;

// ---------------------------------------------------------------------------
// Main combinational encryption block
// ---------------------------------------------------------------------------
always @(*) begin : AES_ENC
    reg [127:0] st;
    reg [127:0] rk;

    // ---- Key Expansion (FIPS-197 §5.2) ----
    w[0] = key[127:96];
    w[1] = key[95:64];
    w[2] = key[63:32];
    w[3] = key[31:0];

    for (i = 4; i < 44; i = i + 1) begin
        if (i % 4 == 0)
            w[i] = w[i-4] ^ (sub_word_f(rot_word_f(w[i-1])) ^ {rcon_f(i/4), 24'h0});
        else
            w[i] = w[i-4] ^ w[i-1];
    end

    // ---- Initial AddRoundKey ----
    st = plaintext ^ {w[0], w[1], w[2], w[3]};

    // ---- Rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey ----
    for (i = 1; i <= 9; i = i + 1) begin
        st = sub_bytes_f(st);
        st = shift_rows_f(st);
        st = mix_columns_f(st);
        rk = {w[4*i], w[4*i+1], w[4*i+2], w[4*i+3]};
        st = st ^ rk;
    end

    // ---- Round 10: SubBytes, ShiftRows, AddRoundKey (no MixColumns) ----
    st = sub_bytes_f(st);
    st = shift_rows_f(st);
    st = st ^ {w[40], w[41], w[42], w[43]};

    ciphertext = st;
end

endmodule
