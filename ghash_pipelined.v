`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04.03.2026 21:45:15
// Design Name: 
// Module Name: ghash_pipelined
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
// ghash_pipelined.v
// Pipelined GHASH Module for AES-GCM
//
// Architecture (from paper):
//   Uses the 4-stage pipelined GF(2^128) multiplier.
//   GHASH formula: Y_i = (Y_{i-1} XOR X_i) * H
//
//   Because the GF multiplier has 4-cycle latency, consecutive blocks cannot
//   be chained directly. The module handles this by:
//   - Accepting 1 block per clock (data_valid strobe, back-pressure via ready)
//   - Inserting wait states to properly chain results
//
//   For simplicity and correctness, this module accepts 1 block per 4+1=5
//   cycles (one multiply finishes before next starts). In the high-throughput
//   top module the GHASH is fed at the same rate as CT blocks arrive, but the
//   pipeline stalls GHASH until the multiplier is free.
//
//   Ports:
//     clk, rst_n
//     H[127:0]       - hash subkey (AES(K,0)), must be stable
//     data_in[127:0] - 128-bit input block
//     data_valid     - pulse high for one cycle when data_in is valid
//     ready          - high when module can accept a new block (back-pressure)
//     hash_out[127:0]- running GHASH state
//     hash_valid     - high for one cycle when hash_out is the final of a block
// =============================================================================

module ghash_pipelined (
    input             clk,
    input             rst_n,
    input  [127:0]    H,
    input  [127:0]    data_in,
    input             data_valid,
    output            ready,
    output [127:0]    hash_out,
    output reg        hash_valid
);

// ---------------------------------------------------------------------------
// State machine: IDLE -> BUSY (4 cycles wait for GF mul) -> IDLE
// ---------------------------------------------------------------------------
localparam IDLE = 1'b0;
localparam BUSY = 1'b1;

reg         state;
reg [2:0]   latency_cnt;   // counts GF mul pipeline latency (4 cycles)

// Accumulated GHASH state
reg  [127:0] ghash_state;

// Intermediate signals to/from GF multiplier
reg  [127:0] gf_X_reg, gf_Y_reg;
reg          gf_valid_in;
wire [127:0] gf_Z;
wire         gf_valid_out;

// Instantiate pipelined GF multiplier
gf128_mul_pipelined GF_MUL (
    .clk      (clk),
    .rst_n    (rst_n),
    .X        (gf_X_reg),
    .Y        (gf_Y_reg),
    .valid_in (gf_valid_in),
    .Z        (gf_Z),
    .valid_out(gf_valid_out)
);

// ready when in IDLE state
assign ready = (state == IDLE);

// Main FSM
always @(posedge clk) begin
    if (!rst_n) begin
        state       <= IDLE;
        latency_cnt <= 3'd0;
        ghash_state <= 128'h0;
        gf_X_reg    <= 128'h0;
        gf_Y_reg    <= 128'h0;
        gf_valid_in <= 1'b0;
        hash_valid  <= 1'b0;
    end else begin
        gf_valid_in <= 1'b0;
        hash_valid  <= 1'b0;

        case (state)
            IDLE: begin
                if (data_valid) begin
                    // Launch GF multiply: (ghash_state XOR data_in) * H
                    gf_X_reg    <= ghash_state ^ data_in;
                    gf_Y_reg    <= H;
                    gf_valid_in <= 1'b1;
                    latency_cnt <= 3'd0;
                    state       <= BUSY;
                end
            end

            BUSY: begin
                latency_cnt <= latency_cnt + 3'd1;
                // Wait for gf_valid_out (4 cycles after gf_valid_in)
                if (gf_valid_out) begin
                    ghash_state <= gf_Z;
                    hash_valid  <= 1'b1;
                    state       <= IDLE;
                end
            end

            default: state <= IDLE;
        endcase
    end
end

assign hash_out = ghash_state;

endmodule

