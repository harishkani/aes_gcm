`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04.03.2026 21:43:42
// Design Name: 
// Module Name: gf128_mul_pipelined
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
// gf128_mul_pipelined.v
// Pipelined GF(2^128) Multiplier - 4 pipeline stages
//
// Architecture (from paper):
//   The 128-bit serial multiply (Z = X * Y in GF(2^128)) is split into
//   4 pipeline stages of 32 iterations each.
//
//   GCM irreducible polynomial (NIST SP 800-38D):
//     f(x) = x^128 + x^7 + x^2 + x + 1
//   Reduction constant R = 0xE1000...0 (128 bits)
//
//   Bit convention: leftmost bit of spec = Verilog bit[127]
//
//   Algorithm (GCM spec Algorithm 1, unrolled across 4 stages):
//     Z = 0, V = X
//     for i = 0..127:
//       if Y[127-i]: Z = Z ^ V
//       if V[0]==0 : V = V >> 1
//       else       : V = (V >> 1) ^ R
//
// Pipeline:
//   Stage 0 (input regs): latch X, Y
//   Stage 1: iterations  0-31  -> Z1, V1 (registered)
//   Stage 2: iterations 32-63  -> Z2, V2 (registered)
//   Stage 3: iterations 64-95  -> Z3, V3 (registered)
//   Stage 4: iterations 96-127 -> Z_out  (registered)
//
//   Latency  = 4 clock cycles
//   Throughput = 1 multiplication/clock
//
// Ports:
//   clk          - clock
//   rst_n        - active-low synchronous reset
//   X, Y         - 128-bit operands
//   valid_in     - high when X,Y are valid
//   Z            - 128-bit product output
//   valid_out    - high when Z is valid (4 cycles after valid_in)
// =============================================================================

module gf128_mul_pipelined (
    input             clk,
    input             rst_n,
    input  [127:0]    X,
    input  [127:0]    Y,
    input             valid_in,
    output [127:0]    Z,
    output            valid_out
);

// Reduction polynomial
localparam [127:0] R = 128'he1000000000000000000000000000000;

// ---------------------------------------------------------------------------
// Helper: run N iterations of the GF-mul algorithm starting from (Zi, Vi, Yi)
//   Yi is the slice of Y bits relevant to these iterations (Yi[127-base .. 127-base-N+1])
//   Returns the new Z and V after N iterations
// Because we can't return two values from a Verilog function, we use a task
// inside a generate block and unroll via a local wire array.
// We use a purely combinational wire array per stage to iterate.
// ---------------------------------------------------------------------------

// ---- Stage 0: register inputs ----
reg [127:0] s0_X, s0_Y;
reg         s0_valid;

always @(posedge clk) begin
    if (!rst_n) begin
        s0_X     <= 128'h0;
        s0_Y     <= 128'h0;
        s0_valid <= 1'b0;
    end else begin
        s0_X     <= X;
        s0_Y     <= Y;
        s0_valid <= valid_in;
    end
end

// ---------------------------------------------------------------------------
// Combinational helper: perform 32 GF-mul iterations given (Zin, Vin, Ybits)
// Ybits[31] corresponds to Y[127-base_iter], Ybits[0] = Y[127-base_iter-31]
// Returns (Zout, Vout)
// Uses a local wire array of depth 33.
// ---------------------------------------------------------------------------

// ---- Stage 1: iterations 0-31 ----
wire [127:0] s1z [0:32];
wire [127:0] s1v [0:32];

assign s1z[0] = 128'h0;
assign s1v[0] = s0_X;

genvar i1;
generate
    for (i1 = 0; i1 < 32; i1 = i1 + 1) begin : S1_ITER
        wire yi      = s0_Y[127 - i1];
        wire [127:0] zn = yi ? (s1z[i1] ^ s1v[i1]) : s1z[i1];
        wire v_lsb   = s1v[i1][0];
        wire [127:0] vs = {1'b0, s1v[i1][127:1]};
        assign s1z[i1+1] = zn;
        assign s1v[i1+1] = v_lsb ? (vs ^ R) : vs;
    end
endgenerate

reg [127:0] r1_Z, r1_V, r1_Y;
reg         r1_valid;

always @(posedge clk) begin
    if (!rst_n) begin
        r1_Z <= 0; r1_V <= 0; r1_Y <= 0; r1_valid <= 0;
    end else begin
        r1_Z     <= s1z[32];
        r1_V     <= s1v[32];
        r1_Y     <= s0_Y;
        r1_valid <= s0_valid;
    end
end

// ---- Stage 2: iterations 32-63 ----
wire [127:0] s2z [0:32];
wire [127:0] s2v [0:32];

assign s2z[0] = r1_Z;
assign s2v[0] = r1_V;

genvar i2;
generate
    for (i2 = 0; i2 < 32; i2 = i2 + 1) begin : S2_ITER
        wire yi      = r1_Y[127 - (32 + i2)];
        wire [127:0] zn = yi ? (s2z[i2] ^ s2v[i2]) : s2z[i2];
        wire v_lsb   = s2v[i2][0];
        wire [127:0] vs = {1'b0, s2v[i2][127:1]};
        assign s2z[i2+1] = zn;
        assign s2v[i2+1] = v_lsb ? (vs ^ R) : vs;
    end
endgenerate

reg [127:0] r2_Z, r2_V, r2_Y;
reg         r2_valid;

always @(posedge clk) begin
    if (!rst_n) begin
        r2_Z <= 0; r2_V <= 0; r2_Y <= 0; r2_valid <= 0;
    end else begin
        r2_Z     <= s2z[32];
        r2_V     <= s2v[32];
        r2_Y     <= r1_Y;
        r2_valid <= r1_valid;
    end
end

// ---- Stage 3: iterations 64-95 ----
wire [127:0] s3z [0:32];
wire [127:0] s3v [0:32];

assign s3z[0] = r2_Z;
assign s3v[0] = r2_V;

genvar i3;
generate
    for (i3 = 0; i3 < 32; i3 = i3 + 1) begin : S3_ITER
        wire yi      = r2_Y[127 - (64 + i3)];
        wire [127:0] zn = yi ? (s3z[i3] ^ s3v[i3]) : s3z[i3];
        wire v_lsb   = s3v[i3][0];
        wire [127:0] vs = {1'b0, s3v[i3][127:1]};
        assign s3z[i3+1] = zn;
        assign s3v[i3+1] = v_lsb ? (vs ^ R) : vs;
    end
endgenerate

reg [127:0] r3_Z, r3_V, r3_Y;
reg         r3_valid;

always @(posedge clk) begin
    if (!rst_n) begin
        r3_Z <= 0; r3_V <= 0; r3_Y <= 0; r3_valid <= 0;
    end else begin
        r3_Z     <= s3z[32];
        r3_V     <= s3v[32];
        r3_Y     <= r2_Y;
        r3_valid <= r2_valid;
    end
end

// ---- Stage 4: iterations 96-127 -> final product ----
wire [127:0] s4z [0:32];
wire [127:0] s4v [0:32];

assign s4z[0] = r3_Z;
assign s4v[0] = r3_V;

genvar i4;
generate
    for (i4 = 0; i4 < 32; i4 = i4 + 1) begin : S4_ITER
        wire yi      = r3_Y[127 - (96 + i4)];
        wire [127:0] zn = yi ? (s4z[i4] ^ s4v[i4]) : s4z[i4];
        wire v_lsb   = s4v[i4][0];
        wire [127:0] vs = {1'b0, s4v[i4][127:1]};
        assign s4z[i4+1] = zn;
        assign s4v[i4+1] = v_lsb ? (vs ^ R) : vs;
    end
endgenerate

reg [127:0] r4_Z;
reg         r4_valid;

always @(posedge clk) begin
    if (!rst_n) begin
        r4_Z     <= 0;
        r4_valid <= 0;
    end else begin
        r4_Z     <= s4z[32];
        r4_valid <= r3_valid;
    end
end

assign Z         = r4_Z;
assign valid_out = r4_valid;

endmodule
