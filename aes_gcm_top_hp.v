`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 04.03.2026 21:38:15
// Design Name: 
// Module Name: aes_gcm_top_hp
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
// aes_gcm_top_hp.v  - High-Throughput AES-128-GCM Top Module
//
// Key design choices:
//   - Dedicated AES pipeline (AES_INIT) computes H=AES(K,0) and EY0=AES(K,Y0)
//   - GCTR module (separate AES pipeline) generates CTR-mode ciphertext
//   - Pipelined GHASH authenticates AAD and CT blocks
//   - pt_valid_gated: WIRE = (state==S_DATA) & pt_valid (prevents pre-S_DATA CT)
//   - S_WAIT_CTR: one extra cycle between gctr_load and S_DATA entry prevents
//     the counter register from being stale when AES first reads it
//   - ct_ghash_done: REGISTERED flag set ONE CYCLE AFTER ct_ghash_cnt==n_pt_r
//     AND ghash_ready=1; prevents S_LEN from racing with the last CT→GHASH feed
// =============================================================================

module aes_gcm_top_hp (
    input             clk,
    input             rst_n,

    input             go,
    input  [127:0]    key,
    input  [95:0]     iv,
    input  [3:0]      n_aad,
    input  [3:0]      n_pt,

    input  [127:0]    aad_in,
    input             aad_valid,
    output            aad_ready,

    input  [127:0]    pt_in,
    input             pt_valid,
    output            pt_ready,

    output reg [127:0] ct_out,
    output reg         ct_valid,

    output reg [127:0] tag_out,
    output reg         done
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
wire [127:0] Y0 = {iv, 31'h0, 1'b1};

function [127:0] incr32;
    input [127:0] c;
    incr32 = {c[127:32], c[31:0] + 32'd1};
endfunction

// ---------------------------------------------------------------------------
// State encoding
// ---------------------------------------------------------------------------
localparam [3:0]
    S_IDLE    = 4'd0,
    S_INIT0   = 4'd1,
    S_INIT1   = 4'd2,
    S_WAIT_H  = 4'd3,
    S_GRST    = 4'd4,
    S_WAIT_CTR= 4'd5,
    S_AAD     = 4'd6,
    S_DATA    = 4'd7,
    S_LEN     = 4'd8,
    S_WAIT_G  = 4'd9,
    S_TAG     = 4'd10,
    S_DONE    = 4'd11;

reg [3:0] state;

// ---------------------------------------------------------------------------
// Dedicated AES pipeline for init
// ---------------------------------------------------------------------------
reg  [127:0] init_aes_in;
reg          init_aes_valid;
wire [127:0] init_aes_out;
wire         init_aes_vout;

aes128_core_pipelined AES_INIT (
    .clk      (clk),
    .rst_n    (rst_n),
    .key      (key),
    .pt_in    (init_aes_in),
    .pt_valid (init_aes_valid),
    .ct_out   (init_aes_out),
    .ct_valid (init_aes_vout)
);

// ---------------------------------------------------------------------------
// GCTR - separate AES pipeline
// ---------------------------------------------------------------------------
wire [127:0] gctr_ct;
wire         gctr_ct_v;
reg  [127:0] gctr_start_ctr;
reg          gctr_load;

gctr GCTR_INST (
    .clk       (clk),
    .rst_n     (rst_n),
    .key       (key),
    .start_ctr (gctr_start_ctr),
    .load_ctr  (gctr_load),
    .pt_in     (pt_in),
    .pt_valid  (pt_valid),
    .in_data_state(state == S_DATA),
    .ct_out    (gctr_ct),
    .ct_valid  (gctr_ct_v)
);

// ---------------------------------------------------------------------------
// Pipelined GHASH
// ---------------------------------------------------------------------------
reg  [127:0] ghash_H;
reg  [127:0] ghash_din;
reg          ghash_vin;
reg          ghash_rstn;
wire [127:0] ghash_out;
wire         ghash_hv;
wire         ghash_ready;

ghash_pipelined GHASH_INST (
    .clk       (clk),
    .rst_n     (ghash_rstn),
    .H         (ghash_H),
    .data_in   (ghash_din),
    .data_valid(ghash_vin),
    .ready     (ghash_ready),
    .hash_out  (ghash_out),
    .hash_valid(ghash_hv)
);

// ---------------------------------------------------------------------------
// Control registers
// ---------------------------------------------------------------------------
reg [3:0]   aad_cnt;
reg [3:0]   pt_cnt;
reg [3:0]   n_aad_r, n_pt_r;
reg         got_H;
reg [127:0] H_reg, EY0_reg;
reg [3:0]   ct_ghash_cnt;   // # CT blocks fed to GHASH
reg         ct_ghash_done;  // REGISTERED: high one cycle after last CT finished

wire [127:0] len_block = { {53'h0, n_aad_r, 7'h0},
                            {53'h0, n_pt_r,  7'h0} };

// ---------------------------------------------------------------------------
// GCTR -> GHASH FIFO (Depth 16)
// To handle back-to-back CT blocks arriving 1/cycle while GHASH takes 5/cycle
// ---------------------------------------------------------------------------
reg [127:0] fifo_data [0:15];
reg [3:0]   fifo_wr;
reg [3:0]   fifo_rd;
reg [4:0]   fifo_cnt;

// Note: fifo_pop uses state != S_IDLE to ensure cleanly flushing.
wire fifo_push = gctr_ct_v;
wire fifo_pop  = (fifo_cnt > 0) && ghash_ready && (ct_ghash_cnt < n_pt_r) && (state != S_IDLE);

// ---------------------------------------------------------------------------
// Sequential logic
// ---------------------------------------------------------------------------
always @(posedge clk) begin
    if (!rst_n) begin
        state          <= S_IDLE;
        done           <= 1'b0;
        ct_valid       <= 1'b0;
        ct_out         <= 128'h0;
        tag_out        <= 128'h0;
        ghash_vin      <= 1'b0;
        ghash_din      <= 128'h0;
        ghash_H        <= 128'h0;
        ghash_rstn     <= 1'b0;
        gctr_load      <= 1'b0;
        gctr_start_ctr <= 128'h0;
        init_aes_in    <= 128'h0;
        init_aes_valid <= 1'b0;
        H_reg          <= 128'h0;
        EY0_reg        <= 128'h0;
        got_H          <= 1'b0;
        aad_cnt        <= 4'd0;
        pt_cnt         <= 4'd0;
        ct_ghash_cnt   <= 4'd0;
        ct_ghash_done  <= 1'b0;
        n_aad_r        <= 4'd0;
        n_pt_r         <= 4'd0;
        fifo_wr        <= 4'd0;
        fifo_rd        <= 4'd0;
        fifo_cnt       <= 5'd0;
    end else begin
        // ------------------------------------------------------------------
        // Default de-asserts
        // ------------------------------------------------------------------
        done           <= 1'b0;
        ct_valid       <= 1'b0;
        ghash_vin      <= 1'b0;
        gctr_load      <= 1'b0;
        init_aes_valid <= 1'b0;

        // ------------------------------------------------------------------
        // GCTR output → CT port and push to FIFO
        // ------------------------------------------------------------------
        if (gctr_ct_v) begin
            ct_out   <= gctr_ct;
            ct_valid <= 1'b1;
        end

        if (fifo_push) begin
            fifo_data[fifo_wr] <= gctr_ct;
            fifo_wr <= fifo_wr + 4'd1;
        end
        if (fifo_pop) begin
            ghash_din     <= fifo_data[fifo_rd];
            ghash_vin     <= 1'b1;
            ct_ghash_cnt  <= ct_ghash_cnt + 4'd1;
            fifo_rd <= fifo_rd + 4'd1;
            ct_ghash_done <= 1'b0;
        end
        
        if (fifo_push && !fifo_pop)
            fifo_cnt <= fifo_cnt + 5'd1;
        else if (!fifo_push && fifo_pop)
            fifo_cnt <= fifo_cnt - 5'd1;

        // ------------------------------------------------------------------
        // Set ct_ghash_done ONE FULL CYCLE after ct_ghash_cnt reaches n_pt_r
        // and GHASH is idle (not transitioning). This avoids the race where
        // the CT→GHASH feed and the len block fire in the same cycle.
        // ------------------------------------------------------------------
        if (ct_ghash_cnt == n_pt_r && n_pt_r != 4'd0 &&
            ghash_ready && !fifo_pop)
            ct_ghash_done <= 1'b1;

        // ------------------------------------------------------------------
        // State machine
        // ------------------------------------------------------------------
        case (state)

            S_IDLE: begin
                ghash_rstn    <= 1'b0;
                ct_ghash_done <= 1'b0;
                if (go) begin
                    n_aad_r      <= n_aad;
                    n_pt_r       <= n_pt;
                    got_H        <= 1'b0;
                    aad_cnt      <= 4'd0;
                    pt_cnt       <= 4'd0;
                    ct_ghash_cnt <= 4'd0;
                    state        <= S_INIT0;
                end
            end

            S_INIT0: begin
                init_aes_in    <= 128'h0;
                init_aes_valid <= 1'b1;
                state          <= S_INIT1;
            end

            S_INIT1: begin
                init_aes_in    <= Y0;
                init_aes_valid <= 1'b1;
                state          <= S_WAIT_H;
            end

            S_WAIT_H: begin
                if (init_aes_vout) begin
                    if (!got_H) begin
                        H_reg <= init_aes_out;
                        got_H <= 1'b1;
                    end else begin
                        EY0_reg        <= init_aes_out;
                        ghash_H        <= H_reg;
                        gctr_start_ctr <= incr32(Y0);
                        state          <= S_GRST;
                    end
                end
            end

            S_GRST: begin
                ghash_rstn <= 1'b1;  // persistent until S_IDLE
                gctr_load  <= 1'b1;
                state      <= S_WAIT_CTR;
            end

            // One-cycle gap after gctr_load so counter register settles before
            // pt_valid_gated can fire in S_DATA
            S_WAIT_CTR: begin
                if (n_aad_r != 4'd0)
                    state <= S_AAD;
                else if (n_pt_r != 4'd0)
                    state <= S_DATA;
                else begin
                    ct_ghash_done <= 1'b1;  // no PT: no CT to wait for
                    state <= S_LEN;
                end
            end

            S_AAD: begin
                if (aad_valid && ghash_ready && !gctr_ct_v) begin
                    ghash_din <= aad_in;
                    ghash_vin <= 1'b1;
                    aad_cnt   <= aad_cnt + 4'd1;
                    if (aad_cnt == n_aad_r - 4'd1)
                        state <= (n_pt_r != 4'd0) ? S_DATA : S_LEN;
                end
            end

            S_DATA: begin
                // Accept blocks and increment counter
                if (pt_valid && pt_ready) begin
                    pt_cnt <= pt_cnt + 4'd1;
                    // Transition exactly after accepting n_pt blocks
                    if (pt_cnt == n_pt_r - 4'd1) begin
                        state <= S_LEN;
                    end
                end else if (n_pt_r == 4'd0) begin
                    state <= S_LEN;
                end
            end

            // Wait until ct_ghash_done (registered: GHASH was idle for a
            // full cycle after last CT), then send len block
            S_LEN: begin
                if (ct_ghash_done && ghash_ready) begin
                    ghash_din     <= len_block;
                    ghash_vin     <= 1'b1;
                    ct_ghash_done <= 1'b0;
                    state         <= S_WAIT_G;
                end
            end

            S_WAIT_G: begin
                if (ghash_hv)
                    state <= S_TAG;
            end

            S_TAG: begin
                tag_out <= ghash_out ^ EY0_reg;
                done    <= 1'b1;
                state   <= S_DONE;
            end

            S_DONE: begin
                done  <= 1'b0;
                state <= S_IDLE;
            end

            default: state <= S_IDLE;
        endcase
    end
end

assign pt_ready  = (state == S_DATA);
assign aad_ready = (state == S_AAD) && ghash_ready && !gctr_ct_v;

endmodule

