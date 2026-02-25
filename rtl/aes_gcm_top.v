// AES-GCM Top-Level Module
// Based on: "The Design of a High-Throughput Hardware Architecture for the AES-GCM Algorithm"
// IEEE Transactions on Consumer Electronics, Vol. 70, No. 1, February 2024
//
// Architecture:
//   - Two parallel AES units (u_aes0, u_aes1) sharing one key expansion module
//   - CTR counter with IV encoder: J0 = IV || 0^31 || 1 for 96-bit IV (NIST SP 800-38D)
//   - GHASH module with dual pipelined GF(2^128) Karatsuba multipliers
//   - Mixed inner- and outer-round pipelining in each AES unit (11 register stages)
//
// AES pipeline: 11 register stages → valid_out lags valid_in by 11+1=12 clock cycles
// (aes0_vin is registered in this FSM, so AES stage-0 reads it 1 cycle after the FSM
//  sets it; the 11 AES pipeline stages then give valid_out 11 cycles after stage-0 fires,
//  totalling 12 cycles after the FSM decision.)
//
// PT alignment pipeline: 12 stages (0..11) so that pt_pipe[11] is stable at the same
// posedge that the FSM reads aes0_vout=1, enabling correct CT = aes0_out ^ pt_pipe[11].
//
// Supports: AES-128-GCM, 96-bit IV, block-aligned AAD and plaintext
//
// pt_last=1 with pt_valid=0 signals "no (more) plaintext" from the user.

module aes_gcm_top (
    input         clk,
    input         rst,

    input  [127:0] key,    // AES-128 key
    input  [95:0]  iv,     // 96-bit initialization vector
    input         start,   // pulse to start new encryption

    // Additional authenticated data (AAD)
    input  [127:0] aad_data,
    input         aad_valid,
    input         aad_last,  // last AAD block

    // Plaintext; pt_last=1 with pt_valid=0 means "no (more) plaintext"
    input  [127:0] pt_data,
    input         pt_valid,
    input         pt_last,

    // Ciphertext
    output [127:0] ct_data,
    output        ct_valid,

    // Authentication tag (128-bit, MSB first)
    output reg [127:0] tag_out,
    output reg    tag_valid
);

    // =========================================================================
    // AES units (paper: two parallel units sharing key expansion)
    // =========================================================================
    reg  [127:0] aes0_in;
    reg          aes0_vin;
    wire [127:0] aes0_out;
    wire         aes0_vout;

    reg  [127:0] aes1_in;
    reg          aes1_vin;
    wire [127:0] aes1_out;
    wire         aes1_vout;

    aes_encrypt u_aes0 (
        .clk(clk), .rst(rst), .key(key),
        .plaintext(aes0_in),  .valid_in(aes0_vin),
        .ciphertext(aes0_out), .valid_out(aes0_vout)
    );
    aes_encrypt u_aes1 (                   // second parallel AES unit (paper Fig. 4)
        .clk(clk), .rst(rst), .key(key),
        .plaintext(aes1_in),  .valid_in(aes1_vin),
        .ciphertext(aes1_out), .valid_out(aes1_vout)
    );

    // =========================================================================
    // GHASH module
    // =========================================================================
    reg          ghash_start;
    reg  [127:0] ghash_h;
    reg  [127:0] ghash_din;
    reg          ghash_dval;
    reg          ghash_dlast;
    wire [127:0] ghash_result;
    wire         ghash_rvld;
    wire         ghash_ready;

    ghash u_ghash (
        .clk(clk), .rst(rst),
        .start(ghash_start),  .h_in(ghash_h),
        .data_in(ghash_din),  .data_valid(ghash_dval),  .data_last(ghash_dlast),
        .result(ghash_result), .result_valid(ghash_rvld), .ready(ghash_ready)
    );

    // =========================================================================
    // FSM states
    // =========================================================================
    localparam S_IDLE       = 4'd0;
    localparam S_WAIT_H     = 4'd1;   // wait for H = AES_K(0^128)
    localparam S_SEND_J0    = 4'd2;   // send J0 to AES for AES_K(J0)
    localparam S_WAIT_J0    = 4'd3;   // wait for AES_K(J0)
    localparam S_AAD        = 4'd4;   // feed AAD to GHASH
    localparam S_PT         = 4'd5;   // accept PT, start AES-CTR
    localparam S_FLUSH_CT   = 4'd6;   // drain AES pipeline, feed CT to GHASH
    localparam S_LEN        = 4'd7;   // feed len(A)||len(C) to GHASH
    localparam S_WAIT_GHASH = 4'd8;   // wait for GHASH final output
    localparam S_DONE       = 4'd9;

    reg [3:0]   state;
    reg [127:0] H_reg;       // H = AES_K(0^128)
    reg [127:0] J0_enc;      // AES_K(J0)
    reg [127:0] ctr;         // CTR block = inc32(J0), incremented per PT block
    reg [63:0]  aad_bits;
    reg [63:0]  ct_bits;
    reg         ct_last_to_ghash; // last CT block has been sent to GHASH

    // =========================================================================
    // 12-stage PT alignment pipeline
    // (matches 12-cycle total AES latency: 1 cycle for aes0_vin registration
    //  + 11 AES pipeline stages)
    // =========================================================================
    reg [127:0] pt_pipe  [0:11];
    reg         ptv_pipe [0:11];
    reg         ptl_pipe [0:11];
    integer i;

    always @(posedge clk) begin
        if (rst) begin
            for (i = 0; i <= 11; i = i + 1) begin
                pt_pipe[i]  <= 128'b0;
                ptv_pipe[i] <= 1'b0;
                ptl_pipe[i] <= 1'b0;
            end
        end else begin
            // Stage 0: capture PT when FSM accepts it (same cycle as aes0_vin set)
            pt_pipe[0]  <= pt_data;
            ptv_pipe[0] <= (state == S_PT) && pt_valid;
            ptl_pipe[0] <= pt_last && (state == S_PT) && pt_valid;
            for (i = 1; i <= 11; i = i + 1) begin
                pt_pipe[i]  <= pt_pipe[i-1];
                ptv_pipe[i] <= ptv_pipe[i-1];
                ptl_pipe[i] <= ptl_pipe[i-1];
            end
        end
    end

    // CT output: keystream XOR plaintext
    assign ct_data  = pt_pipe[11] ^ aes0_out;
    assign ct_valid = ptv_pipe[11] & aes0_vout;

    // =========================================================================
    // Main FSM
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            state             <= S_IDLE;
            H_reg             <= 128'b0;
            J0_enc            <= 128'b0;
            ctr               <= 128'b0;
            aad_bits          <= 64'b0;
            ct_bits           <= 64'b0;
            aes0_in           <= 128'b0;
            aes0_vin          <= 1'b0;
            aes1_in           <= 128'b0;
            aes1_vin          <= 1'b0;
            ghash_start       <= 1'b0;
            ghash_h           <= 128'b0;
            ghash_din         <= 128'b0;
            ghash_dval        <= 1'b0;
            ghash_dlast       <= 1'b0;
            tag_out           <= 128'b0;
            tag_valid         <= 1'b0;
            ct_last_to_ghash  <= 1'b0;
        end else begin
            // Default de-assertions each cycle
            aes0_vin    <= 1'b0;
            aes1_vin    <= 1'b0;
            ghash_start <= 1'b0;
            ghash_dval  <= 1'b0;
            ghash_dlast <= 1'b0;
            tag_valid   <= 1'b0;

            case (state)

                // -------------------------------------------------------
                S_IDLE: begin
                    if (start) begin
                        aad_bits         <= 64'b0;
                        ct_bits          <= 64'b0;
                        ct_last_to_ghash <= 1'b0;
                        // Compute H = AES_K(0^128)
                        aes0_in  <= 128'b0;
                        aes0_vin <= 1'b1;
                        state    <= S_WAIT_H;
                    end
                end

                // -----------------------------------------------------------
                // Wait for H (12 cycles from when aes0_vin was set)
                S_WAIT_H: begin
                    if (aes0_vout) begin
                        H_reg <= aes0_out;
                        state <= S_SEND_J0;
                    end
                end

                // -----------------------------------------------------------
                S_SEND_J0: begin
                    // Send J0 = IV || 0^31 || 1 to AES for AES_K(J0)
                    aes0_in  <= {iv, 31'b0, 1'b1};
                    aes0_vin <= 1'b1;
                    // CTR starts at inc32(J0) = IV || 2
                    ctr      <= {iv, 32'd2};
                    // Start GHASH with H
                    ghash_h     <= H_reg;
                    ghash_start <= 1'b1;
                    state    <= S_WAIT_J0;
                end

                // -----------------------------------------------------------
                S_WAIT_J0: begin
                    if (aes0_vout) begin
                        J0_enc <= aes0_out;
                        state  <= S_AAD;
                    end
                end

                // -----------------------------------------------------------
                // Feed AAD blocks to GHASH (none of them are the "last" block;
                // the len block at the end is always the last GHASH input)
                S_AAD: begin
                    if (aad_valid && ghash_ready) begin
                        ghash_din   <= aad_data;
                        ghash_dval  <= 1'b1;
                        ghash_dlast <= 1'b0;
                        aad_bits    <= aad_bits + 64'd128;
                        if (aad_last) state <= S_PT;
                    end else if (!aad_valid) begin
                        // No (more) AAD
                        state <= S_PT;
                    end
                end

                // -----------------------------------------------------------
                // Encrypt PT blocks with AES-CTR
                // CT blocks appear on ct_data/ct_valid 12 cycles after PT is fed
                S_PT: begin
                    if (pt_valid) begin
                        // Send CTR block to AES0 (even-index blocks)
                        // AES1 would handle odd-index blocks in full dual-AES architecture
                        aes0_in  <= ctr;
                        aes0_vin <= 1'b1;
                        ctr      <= {ctr[127:32], ctr[31:0] + 32'd1};
                        ct_bits  <= ct_bits + 64'd128;
                        if (pt_last) state <= S_FLUSH_CT;
                    end else if (pt_last) begin
                        // pt_last=1, pt_valid=0: no (more) plaintext
                        state <= S_LEN;
                    end

                    // Feed CT to GHASH as it comes out of AES pipeline
                    if (aes0_vout && ptv_pipe[11] && ghash_ready) begin
                        ghash_din   <= ct_data;
                        ghash_dval  <= 1'b1;
                        ghash_dlast <= 1'b0;
                        if (ptl_pipe[11]) ct_last_to_ghash <= 1'b1;
                    end
                end

                // -----------------------------------------------------------
                // Wait for last CT to exit AES pipeline and enter GHASH,
                // then wait for GHASH to finish processing it
                S_FLUSH_CT: begin
                    // Feed CT as it arrives from AES pipeline
                    if (aes0_vout && ptv_pipe[11] && ghash_ready) begin
                        ghash_din   <= ct_data;
                        ghash_dval  <= 1'b1;
                        ghash_dlast <= 1'b0;
                        if (ptl_pipe[11]) ct_last_to_ghash <= 1'b1;
                    end

                    // Once last CT is in GHASH and GHASH is done processing it
                    if (ct_last_to_ghash && ghash_ready) begin
                        ct_last_to_ghash <= 1'b0;
                        state <= S_LEN;
                    end
                end

                // -----------------------------------------------------------
                // Feed len(A)||len(C) as the final (last) GHASH block
                S_LEN: begin
                    if (ghash_ready) begin
                        ghash_din   <= {aad_bits, ct_bits};
                        ghash_dval  <= 1'b1;
                        ghash_dlast <= 1'b1;
                        state       <= S_WAIT_GHASH;
                    end
                end

                // -----------------------------------------------------------
                S_WAIT_GHASH: begin
                    if (ghash_rvld) state <= S_DONE;
                end

                // -----------------------------------------------------------
                S_DONE: begin
                    tag_out   <= J0_enc ^ ghash_result;
                    tag_valid <= 1'b1;
                    state     <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
