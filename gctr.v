`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04.03.2026 21:42:07
// Design Name: 
// Module Name: gctr
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
// gctr.v  - GCM Counter Mode with 10-stage Pipelined AES
//
// Key fix vs old version:
//   - AES is fed (counter, pt_valid) DIRECTLY on the same clock edge;
//     the old code had a one-extra-register delay that encrypted the wrong CTR.
//   - Counter is loaded from start_ctr when load_ctr is asserted.
//   - Counter increments ONLY on pt_valid (GCM low-32-bit inc).
//   - Plaintext is stored in a 10-deep shift register to align with AES latency.
// =============================================================================

module gctr (
    input             clk,
    input             rst_n,
    input  [127:0]    key,
    input  [127:0]    start_ctr,
    input             load_ctr,
    input  [127:0]    pt_in,
    input             pt_valid,
    input             in_data_state,
    output [127:0]    ct_out,
    output            ct_valid
);

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------
reg [127:0] counter;

function [127:0] incr_ctr;
    input [127:0] c;
    incr_ctr = {c[127:32], c[31:0] + 32'd1};
endfunction

wire [127:0] ks_out;
wire         ks_valid;

// ---------------------------------------------------------------------------
// Feed AES pipeline: on the same cycle pt_valid is high,
// feed the CURRENT counter (before inc) directly into AES.
// ---------------------------------------------------------------------------
aes128_core_pipelined AES_CTR_PIPE (
    .clk      (clk),
    .rst_n    (rst_n),
    .key      (key),
    .pt_in    (counter),       // current counter - combinational read
    .pt_valid (pt_valid && in_data_state),
    .ct_out   (ks_out),
    .ct_valid (ks_valid)
);

// ---------------------------------------------------------------------------
// Update counter: prioritise load_ctr, then increment when PT accepted
// ---------------------------------------------------------------------------
always @(posedge clk) begin
    if (!rst_n) begin
        counter <= 128'h0;
    end else if (load_ctr) begin
        counter <= start_ctr;
    end else if (pt_valid && in_data_state) begin
        counter <= incr_ctr(counter);
    end
end

// ---------------------------------------------------------------------------
// Plaintext shift register - 10 stages to match AES pipeline latency
// ---------------------------------------------------------------------------
reg [127:0] pt_pipe  [0:10];  // 11 deep to match 11-cycle AES latency
reg         pt_v_pipe[0:10];

integer k;
always @(posedge clk) begin
    if (!rst_n) begin
        for (k = 0; k < 11; k = k + 1) begin
            pt_pipe[k]   <= 128'h0;
            pt_v_pipe[k] <= 1'b0;
        end
    end else begin
        pt_pipe[0]   <= pt_in;
        pt_v_pipe[0] <= pt_valid;
        for (k = 1; k < 11; k = k + 1) begin
            pt_pipe[k]   <= pt_pipe[k-1];
            pt_v_pipe[k] <= pt_v_pipe[k-1];
        end
    end
end

// ---------------------------------------------------------------------------
// XOR keystream with aligned plaintext
// ---------------------------------------------------------------------------
assign ct_out   = ks_out ^ pt_pipe[10];   // 11-cycle delay aligns with AES stage_valid[10]
assign ct_valid = ks_valid & pt_v_pipe[10];

endmodule

