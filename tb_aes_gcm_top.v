`timescale 1ns/1ps
// =============================================================================
// tb_aes_gcm_top.v  –  Top-level testbench for aes_gcm_top_hp
//
// Covers all 6 NIST AES-GCM test vectors from Appendix B of the GCM spec
// (128-bit key only).
//
// Design changes required in aes_gcm_top_hp:
//   • iv[95:0]  replaced by y0[127:0]  (caller supplies pre-computed Y0)
//   • aad_len_bits[63:0] / pt_len_bits[63:0] added for correct len-block
//
// TC1 : K=0, P=empty, A=empty, std-96b IV, Y0 trivially {IV||0^31||1}
// TC2 : K=0, P=1×128b, A=empty, std-96b IV
// TC3 : K≠0, P=4×128b, A=empty, std-96b IV
// TC4 : K≠0, P=60 B (partial last blk), A=20 B (partial last blk), std-96b IV
// TC5 : same P/A as TC4, IV=8 B (64-bit, non-standard) – Y0 from test-vec
// TC6 : same P/A as TC4, IV=60 B (480-bit, non-standard) – Y0 from test-vec
// =============================================================================

module tb_aes_gcm_top;

// =========================================================================
// DUT ports
// =========================================================================
reg          clk;
reg          rst_n;
reg          go;
reg  [127:0] key;
reg  [127:0] y0;
reg   [3:0]  n_aad;
reg   [3:0]  n_pt;
reg  [63:0]  aad_len_bits;
reg  [63:0]  pt_len_bits;
reg  [127:0] aad_in;
reg          aad_valid;
reg  [127:0] pt_in;
reg          pt_valid;
wire [127:0] ct_out;
wire         ct_valid;
wire [127:0] tag_out;
wire         done;
wire         aad_ready;
wire         pt_ready;

// =========================================================================
// DUT instantiation
// =========================================================================
aes_gcm_top_hp DUT (
    .clk          (clk),
    .rst_n        (rst_n),
    .go           (go),
    .key          (key),
    .y0           (y0),
    .n_aad        (n_aad),
    .n_pt         (n_pt),
    .aad_len_bits (aad_len_bits),
    .pt_len_bits  (pt_len_bits),
    .aad_in       (aad_in),
    .aad_valid    (aad_valid),
    .aad_ready    (aad_ready),
    .pt_in        (pt_in),
    .pt_valid     (pt_valid),
    .pt_ready     (pt_ready),
    .ct_out       (ct_out),
    .ct_valid     (ct_valid),
    .tag_out      (tag_out),
    .done         (done)
);

// =========================================================================
// Clock  (10 ns period)
// =========================================================================
initial clk = 1'b0;
always  #5 clk = ~clk;

// =========================================================================
// Test book-keeping
// =========================================================================
integer tc_pass;
integer tc_fail;
integer got_ct_cnt;          // how many CT blocks captured so far
reg [127:0] got_ct [0:15];  // captured ciphertext blocks

// Capture CT as it appears (one block per ct_valid pulse)
always @(posedge clk) begin
    if (ct_valid) begin
        got_ct[got_ct_cnt] = ct_out;     // blocking – immediate capture
        got_ct_cnt         = got_ct_cnt + 1;
    end
end

// Shared data arrays written before each run_test call
reg [127:0] aad_data [0:15];
reg [127:0] pt_data  [0:15];
reg [127:0] exp_ct   [0:15];
integer     exp_ct_n;               // expected number of CT blocks
integer     exp_ct_partial_bytes;   // 0 = all full; else # valid bytes in last block

// =========================================================================
// Task: hard reset
// =========================================================================
task do_reset;
begin
    rst_n     = 1'b0;
    go        = 1'b0;
    aad_valid = 1'b0;
    pt_valid  = 1'b0;
    aad_in    = 128'h0;
    pt_in     = 128'h0;
    got_ct_cnt = 0;
    repeat(3) @(posedge clk);
    @(negedge clk); rst_n = 1'b1;
    @(posedge clk);
end
endtask

// =========================================================================
// Task: feed n AAD blocks with valid/ready handshake
//   Waits for aad_ready at a posedge, then presents data at negedge so
//   it is stable when DUT samples on the following posedge.
// =========================================================================
task feed_aad;
    input integer n;
    integer i;
begin
    for (i = 0; i < n; i = i + 1) begin
        // Assert data at negedge so it's stable for the next posedge
        @(negedge clk);
        aad_in    = aad_data[i];
        aad_valid = 1'b1;
        // Wait at posedge until aad_ready is high: block is consumed this cycle
        @(posedge clk);
        while (!aad_ready) @(posedge clk);
        // Deassert after the consuming posedge
        @(negedge clk);
        aad_valid = 1'b0;
        aad_in    = 128'h0;
    end
end
endtask

// =========================================================================
// Task: feed n PT blocks – waits for S_DATA, then back-to-back
// =========================================================================
task feed_pt;
    input integer n;
    integer i;
begin
    if (n > 0) begin
        @(posedge clk);
        while (!pt_ready) @(posedge clk);
        for (i = 0; i < n; i = i + 1) begin
            @(negedge clk);
            pt_in    = pt_data[i];
            pt_valid = 1'b1;
            @(posedge clk);
        end
        @(negedge clk);
        pt_valid = 1'b0;
        pt_in    = 128'h0;
    end
end
endtask

// =========================================================================
// Task: verify CT and tag after 'done'
// =========================================================================
task check_results;
    input [8*80-1:0] tc_name;
    input [127:0]    exp_tag;
    integer i;
    reg [127:0] mask;
    reg tag_ok, ct_ok, blk_ok;
begin
    tag_ok = (tag_out === exp_tag);

    ct_ok = 1'b1;
    if (got_ct_cnt !== exp_ct_n) begin
        $display("  [CT count mismatch] got=%0d exp=%0d", got_ct_cnt, exp_ct_n);
        ct_ok = 1'b0;
    end else begin
        for (i = 0; i < exp_ct_n; i = i + 1) begin
            if (i == exp_ct_n-1 && exp_ct_partial_bytes != 0) begin
                // Mask: only check the first exp_ct_partial_bytes bytes
                // (top bits of 128-bit word)
                mask  = {128{1'b1}} << (8*(16 - exp_ct_partial_bytes));
                blk_ok = ((got_ct[i] & mask) === (exp_ct[i] & mask));
            end else begin
                blk_ok = (got_ct[i] === exp_ct[i]);
            end
            if (!blk_ok) begin
                $display("  [CT blk %0d mismatch] got=%h exp=%h", i, got_ct[i], exp_ct[i]);
                ct_ok = 1'b0;
            end
        end
    end

    if (tag_ok && ct_ok) begin
        $display("  PASS: %0s", tc_name);
        tc_pass = tc_pass + 1;
    end else begin
        $display("  FAIL: %0s", tc_name);
        if (!tag_ok)
            $display("  [Tag  mismatch] got=%h  exp=%h", tag_out, exp_tag);
        tc_fail = tc_fail + 1;
    end
end
endtask

// =========================================================================
// Task: full test runner
//   Sets DUT config, pulses go, feeds data in parallel fork, waits for done
// =========================================================================
task run_test;
    input [8*80-1:0] tc_name;
    input [127:0]    key_i;
    input [127:0]    y0_i;
    input  [3:0]     n_aad_i;
    input  [63:0]    aad_bits_i;
    input  [3:0]     n_pt_i;
    input  [63:0]    pt_bits_i;
    input [127:0]    exp_tag_i;
    integer timeout;
begin
    do_reset;

    // Apply configuration
    key          = key_i;
    y0           = y0_i;
    n_aad        = n_aad_i;
    n_pt         = n_pt_i;
    aad_len_bits = aad_bits_i;
    pt_len_bits  = pt_bits_i;

    // Pulse go
    @(negedge clk); go = 1'b1;
    @(negedge clk); go = 1'b0;

    // Feed AAD and PT concurrently.
    // Because the DUT processes AAD before PT (S_AAD -> S_DATA), the PT
    // thread naturally waits in its while(!pt_ready) loop until AAD is done.
    fork
        feed_aad(n_aad_i);
        feed_pt (n_pt_i);
    join

    // Wait for done with timeout guard
    timeout = 8000;
    @(posedge clk);
    while (!done && timeout > 0) begin
        @(posedge clk);
        timeout = timeout - 1;
    end

    if (timeout == 0)
        $display("  TIMEOUT: %0s", tc_name);
    else
        check_results(tc_name, exp_tag_i);
end
endtask

// =========================================================================
// ---- Test vectors ----
// All values from NIST GCM spec Appendix B (128-bit key tests only)
// =========================================================================
initial begin
    tc_pass = 0;
    tc_fail = 0;

    $display("=================================================");
    $display(" AES-128-GCM testbench  (6 NIST test vectors)");
    $display("=================================================");

    // -----------------------------------------------------------------
    // TC1: K=0, P=empty, A=empty, IV=0 (standard 96-bit)
    //   Y0  = 0x00..001
    //   T   = 0x58e2fccefa7e3061367f1d57a4e7455a
    // -----------------------------------------------------------------
    exp_ct_n             = 0;
    exp_ct_partial_bytes = 0;
    run_test(
        "TC1 (K=0, P=empty, IV=0)",
        128'h00000000000000000000000000000000,   // key
        128'h00000000000000000000000000000001,   // Y0 = {IV||0^31||1}
        4'd0, 64'd0,                             // n_aad, aad_len_bits
        4'd0, 64'd0,                             // n_pt,  pt_len_bits
        128'h58e2fccefa7e3061367f1d57a4e7455a    // expected tag
    );

    // -----------------------------------------------------------------
    // TC2: K=0, P=1 block of zeros, A=empty, IV=0 (standard 96-bit)
    //   C  = 0388dace60b6a392f328c2b971b2fe78
    //   T  = ab6e47d42cec13bdf53a67b21257bddf
    // -----------------------------------------------------------------
    pt_data[0]           = 128'h00000000000000000000000000000000;
    exp_ct[0]            = 128'h0388dace60b6a392f328c2b971b2fe78;
    exp_ct_n             = 1;
    exp_ct_partial_bytes = 0;
    run_test(
        "TC2 (K=0, P=1blk, A=empty, IV=0)",
        128'h00000000000000000000000000000000,
        128'h00000000000000000000000000000001,
        4'd0, 64'd0,
        4'd1, 64'd128,
        128'hab6e47d42cec13bdf53a67b21257bddf
    );

    // -----------------------------------------------------------------
    // TC3: K!=0, P=4 full blocks, A=empty, standard 96-bit IV
    //   C[0..3] as below, T = 4d5c2af327cd64a62cf35abd2ba6fab4
    // -----------------------------------------------------------------
    pt_data[0] = 128'hd9313225f88406e5a55909c5aff5269a;
    pt_data[1] = 128'h86a7a9531534f7da2e4c303d8a318a72;
    pt_data[2] = 128'h1c3c0c95956809532fcf0e2449a6b525;
    pt_data[3] = 128'hb16aedf5aa0de657ba637b391aafd255;
    exp_ct[0]  = 128'h42831ec2217774244b7221b784d0d49c;
    exp_ct[1]  = 128'he3aa212f2c02a4e035c17e2329aca12e;
    exp_ct[2]  = 128'h21d514b25466931c7d8f6a5aac84aa05;
    exp_ct[3]  = 128'h1ba30b396a0aac973d58e091473f5985;
    exp_ct_n             = 4;
    exp_ct_partial_bytes = 0;
    run_test(
        "TC3 (K!=0, P=4blk, A=empty, std-96b-IV)",
        128'hfeffe9928665731c6d6a8f9467308308,
        128'hcafebabefacedbaddecaf88800000001,   // Y0 = {IV||0^31||1}
        4'd0, 64'd0,
        4'd4, 64'd512,                           // 4 blocks = 512 bits
        128'h4d5c2af327cd64a62cf35abd2ba6fab4
    );

    // -----------------------------------------------------------------
    // TC4: K!=0, P=60 B (partial last block), A=20 B, std-96b IV
    //   A block 2 is "abaddad2" zero-padded to 128 bits.
    //   P block 4 is "b16aedf5aa0de657ba637b39" zero-padded to 128 bits.
    //   len(A)=160 bits, len(C)=480 bits.
    //   C[0..2] same as TC3; C[3] first 12 bytes only.
    //   T  = 5bc94fbc3221a5db94fae95ae7121a47
    // -----------------------------------------------------------------
    aad_data[0] = 128'hfeedfacedeadbeeffeedfacedeadbeef;
    aad_data[1] = 128'habaddad2000000000000000000000000; // 4 B + 12 B zero-pad
    pt_data[0]  = 128'hd9313225f88406e5a55909c5aff5269a;
    pt_data[1]  = 128'h86a7a9531534f7da2e4c303d8a318a72;
    pt_data[2]  = 128'h1c3c0c95956809532fcf0e2449a6b525;
    pt_data[3]  = 128'hb16aedf5aa0de657ba637b3900000000; // 12 B + 4 B zero-pad
    exp_ct[0]   = 128'h42831ec2217774244b7221b784d0d49c;
    exp_ct[1]   = 128'he3aa212f2c02a4e035c17e2329aca12e;
    exp_ct[2]   = 128'h21d514b25466931c7d8f6a5aac84aa05;
    exp_ct[3]   = 128'h1ba30b396a0aac973d58e09100000000; // top 12 B checked
    exp_ct_n             = 4;
    exp_ct_partial_bytes = 12;
    run_test(
        "TC4 (K!=0, P=60B, A=20B, std-96b-IV)",
        128'hfeffe9928665731c6d6a8f9467308308,
        128'hcafebabefacedbaddecaf88800000001,
        4'd2, 64'd160,   // 20 bytes = 160 bits
        4'd4, 64'd480,   // 60 bytes = 480 bits
        128'h5bc94fbc3221a5db94fae95ae7121a47
    );

    // -----------------------------------------------------------------
    // TC5: K!=0, P=60 B, A=20 B, non-standard 64-bit IV
    //   IV = cafebabefacedbad  (8 bytes = 64 bits)
    //   Y0 is derived via GHASH: value taken directly from test-vector.
    //   Y0 = c43a83c4c4badec4354ca984db252f7d
    //   T  = 3612d2e79e3b0785561be14aaca2fccb
    // -----------------------------------------------------------------
    aad_data[0] = 128'hfeedfacedeadbeeffeedfacedeadbeef;
    aad_data[1] = 128'habaddad2000000000000000000000000;
    pt_data[0]  = 128'hd9313225f88406e5a55909c5aff5269a;
    pt_data[1]  = 128'h86a7a9531534f7da2e4c303d8a318a72;
    pt_data[2]  = 128'h1c3c0c95956809532fcf0e2449a6b525;
    pt_data[3]  = 128'hb16aedf5aa0de657ba637b3900000000;
    exp_ct[0]   = 128'h61353b4c2806934a777ff51fa22a4755;
    exp_ct[1]   = 128'h699b2a714fcdc6f83766e5f97b6c7423;
    exp_ct[2]   = 128'h73806900e49f24b22b097544d4896b42;
    exp_ct[3]   = 128'h4989b5e1ebac0f07c23f459800000000; // top 12 B checked
    exp_ct_n             = 4;
    exp_ct_partial_bytes = 12;
    run_test(
        "TC5 (K!=0, P=60B, A=20B, 64-bit IV non-std)",
        128'hfeffe9928665731c6d6a8f9467308308,
        128'hc43a83c4c4badec4354ca984db252f7d, // Y0 from NIST test-vector
        4'd2, 64'd160,
        4'd4, 64'd480,
        128'h3612d2e79e3b0785561be14aaca2fccb
    );

    // -----------------------------------------------------------------
    // TC6: K!=0, P=60 B, A=20 B, non-standard 480-bit IV
    //   IV = 9313225d...637b39b  (60 bytes = 480 bits)
    //   Y0 is derived via GHASH: value taken directly from test-vector.
    //   Y0 = 3bab75780a31c059f83d2a44752f9864
    //   T  = 619cc5aefffe0bfa462af43c1699d050
    // -----------------------------------------------------------------
    aad_data[0] = 128'hfeedfacedeadbeeffeedfacedeadbeef;
    aad_data[1] = 128'habaddad2000000000000000000000000;
    pt_data[0]  = 128'hd9313225f88406e5a55909c5aff5269a;
    pt_data[1]  = 128'h86a7a9531534f7da2e4c303d8a318a72;
    pt_data[2]  = 128'h1c3c0c95956809532fcf0e2449a6b525;
    pt_data[3]  = 128'hb16aedf5aa0de657ba637b3900000000;
    exp_ct[0]   = 128'h8ce24998625615b603a033aca13fb894;
    exp_ct[1]   = 128'hbe9112a5c3a211a8ba262a3cca7e2ca7;
    exp_ct[2]   = 128'h01e4a9a4fba43c90ccdcb281d48c7c6f;
    exp_ct[3]   = 128'hd62875d2aca417034c34aee500000000; // top 12 B checked
    exp_ct_n             = 4;
    exp_ct_partial_bytes = 12;
    run_test(
        "TC6 (K!=0, P=60B, A=20B, 480-bit IV non-std)",
        128'hfeffe9928665731c6d6a8f9467308308,
        128'h3bab75780a31c059f83d2a44752f9864, // Y0 from NIST test-vector
        4'd2, 64'd160,
        4'd4, 64'd480,
        128'h619cc5aefffe0bfa462af43c1699d050
    );

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    $display("=================================================");
    $display(" Results: %0d PASS,  %0d FAIL", tc_pass, tc_fail);
    $display("=================================================");
    if (tc_fail == 0)
        $display(" ALL TESTS PASSED");
    else
        $display(" *** %0d TEST(S) FAILED ***", tc_fail);
    $finish;
end

// Hard simulation limit (prevent hang)
initial begin
    #5000000;
    $display("FATAL: absolute simulation timeout");
    $finish;
end

endmodule
