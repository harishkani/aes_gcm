`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04.03.2026 21:39:59
// Design Name: 
// Module Name: aes128_core_pipelined
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////

// =============================================================================
// aes128_core_pipelined.v
// High-Throughput 10-Stage Pipelined AES-128 Encryption Core
//
// Architecture (from paper):
//   - Each of the 10 AES rounds occupies exactly ONE pipeline stage
//   - A 128-bit register separates each stage
//   - Round keys are computed combinationally (key is static after loading)
//   - Latency  = 10 clock cycles
//   - Throughput = 1 block per clock cycle (after pipeline fills)
//
// Port description:
//   clk       - clock
//   rst_n     - active-low synchronous reset
//   key       - 128-bit AES-128 key (must be stable)
//   pt_in     - 128-bit plaintext input
//   pt_valid  - high for one cycle when pt_in is valid
//   ct_out    - 128-bit ciphertext output
//   ct_valid  - high for one cycle when ct_out is valid (10 cycles after pt_valid)
//
// State layout (column-major):
//   col0 = state[127:96], col1 = state[95:64], col2 = state[63:32], col3 = state[31:0]
//   byte[row][col] = state[127 - 32*col - 8*row -: 8]
// =============================================================================

module aes128_core_pipelined (
    input             clk,
    input             rst_n,
    input  [127:0]    key,
    input  [127:0]    pt_in,
    input             pt_valid,
    output [127:0]    ct_out,
    output            ct_valid
);

// ---------------------------------------------------------------------------
// KEY EXPANSION  (fully combinational - key assumed stable)
// Produces round keys rk[0..10], each 128 bits
// ---------------------------------------------------------------------------
wire [31:0] w [0:43];

// Round constants
function [7:0] rcon_byte;
    input [3:0] round;
    case (round)
        4'd1:  rcon_byte = 8'h01;
        4'd2:  rcon_byte = 8'h02;
        4'd3:  rcon_byte = 8'h04;
        4'd4:  rcon_byte = 8'h08;
        4'd5:  rcon_byte = 8'h10;
        4'd6:  rcon_byte = 8'h20;
        4'd7:  rcon_byte = 8'h40;
        4'd8:  rcon_byte = 8'h80;
        4'd9:  rcon_byte = 8'h1b;
        4'd10: rcon_byte = 8'h36;
        default: rcon_byte = 8'h00;
    endcase
endfunction

assign w[0] = key[127:96];
assign w[1] = key[95:64];
assign w[2] = key[63:32];
assign w[3] = key[31:0];

wire [31:0] subword_in  [1:10];
wire [7:0]  sw_b0 [1:10], sw_b1 [1:10], sw_b2 [1:10], sw_b3 [1:10];

genvar gi;
generate
    for (gi = 1; gi <= 10; gi = gi + 1) begin : KEYEXP
        assign subword_in[gi] = {w[4*gi-1][23:0], w[4*gi-1][31:24]}; // RotWord
        aes_sbox KSB0(.in(subword_in[gi][31:24]), .out(sw_b0[gi]));
        aes_sbox KSB1(.in(subword_in[gi][23:16]), .out(sw_b1[gi]));
        aes_sbox KSB2(.in(subword_in[gi][15:8]),  .out(sw_b2[gi]));
        aes_sbox KSB3(.in(subword_in[gi][7:0]),   .out(sw_b3[gi]));

        wire [31:0] temp;
        assign temp = {sw_b0[gi], sw_b1[gi], sw_b2[gi], sw_b3[gi]} ^
                      {rcon_byte(gi[3:0]), 24'h000000};

        assign w[4*gi]   = w[4*gi-4] ^ temp;
        assign w[4*gi+1] = w[4*gi-3] ^ w[4*gi];
        assign w[4*gi+2] = w[4*gi-2] ^ w[4*gi+1];
        assign w[4*gi+3] = w[4*gi-1] ^ w[4*gi+2];
    end
endgenerate

wire [127:0] rk [0:10];
generate
    for (gi = 0; gi <= 10; gi = gi + 1) begin : RKEYS
        assign rk[gi] = {w[4*gi], w[4*gi+1], w[4*gi+2], w[4*gi+3]};
    end
endgenerate

// ---------------------------------------------------------------------------
// ROUND FUNCTION helpers
// ---------------------------------------------------------------------------

// GF(2^8) multiply by 2 (xtime)
function [7:0] xtime;
    input [7:0] b;
    xtime = {b[6:0], 1'b0} ^ (b[7] ? 8'h1b : 8'h00);
endfunction

// MixColumns on one 32-bit column
function [31:0] mix_col;
    input [31:0] col;
    reg [7:0] b0, b1, b2, b3;
    begin
        b0 = col[31:24]; b1 = col[23:16]; b2 = col[15:8]; b3 = col[7:0];
        mix_col = {
            xtime(b0) ^ (xtime(b1)^b1) ^ b2          ^ b3,
            b0        ^ xtime(b1)      ^ (xtime(b2)^b2) ^ b3,
            b0        ^ b1             ^ xtime(b2)      ^ (xtime(b3)^b3),
            (xtime(b0)^b0) ^ b1       ^ b2             ^ xtime(b3)
        };
    end
endfunction

// ---------------------------------------------------------------------------
// PIPELINE STAGES
// stage_state[s]  : 128-bit state entering stage s (after ARK of prev stage)
// stage_valid[s]  : validity bit propagating through pipeline
// ---------------------------------------------------------------------------

// stage_state[0] = ARK with rk[0]  (initial add-round-key)
// stage_state[1..10] = result of round s applied to stage_state[s-1]

reg [127:0] stage_state [0:10];
reg         stage_valid [0:10];

// Stage 0: AddRoundKey rk[0] with plaintext, registered
always @(posedge clk) begin
    if (!rst_n) begin
        stage_state[0] <= 128'h0;
        stage_valid[0] <= 1'b0;
    end else begin
        stage_state[0] <= pt_in ^ rk[0];
        stage_valid[0] <= pt_valid;
    end
end

// Stages 1-10: fully pipelined AES rounds
// Each stage instantiated as a generate block
genvar r;
generate
    for (r = 1; r <= 10; r = r + 1) begin : PIPE_ROUNDS

        // ---------- SubBytes (wire, combinational) ----------
        wire [7:0] sb [0:3][0:3]; // sb[row][col]
        genvar row, col;
        for (row = 0; row <= 3; row = row + 1) begin : SB_ROW
            for (col = 0; col <= 3; col = col + 1) begin : SB_COL
                aes_sbox SB(
                    .in (stage_state[r-1][127 - 32*col - 8*row -: 8]),
                    .out(sb[row][col])
                );
            end
        end

        // ---------- ShiftRows (wire) ----------
        wire [127:0] after_sr;
        assign after_sr = {
            // col0: row0 from col0, row1 from col1, row2 from col2, row3 from col3
            sb[0][0], sb[1][1], sb[2][2], sb[3][3],
            // col1
            sb[0][1], sb[1][2], sb[2][3], sb[3][0],
            // col2
            sb[0][2], sb[1][3], sb[2][0], sb[3][1],
            // col3
            sb[0][3], sb[1][0], sb[2][1], sb[3][2]
        };

        // ---------- MixColumns (wire, skip round 10) ----------
        wire [127:0] after_mc;
        if (r < 10) begin : MC_ON
            assign after_mc = {
                mix_col(after_sr[127:96]),
                mix_col(after_sr[95:64]),
                mix_col(after_sr[63:32]),
                mix_col(after_sr[31:0])
            };
        end else begin : MC_OFF
            assign after_mc = after_sr;
        end

        // ---------- AddRoundKey + Pipeline Register ----------
        always @(posedge clk) begin
            if (!rst_n) begin
                stage_state[r] <= 128'h0;
                stage_valid[r] <= 1'b0;
            end else begin
                stage_state[r] <= after_mc ^ rk[r];
                stage_valid[r] <= stage_valid[r-1];
            end
        end

    end
endgenerate

// ---------------------------------------------------------------------------
// Outputs: ciphertext comes from the last pipeline stage
// ---------------------------------------------------------------------------
assign ct_out   = stage_state[10];
assign ct_valid = stage_valid[10];

endmodule

