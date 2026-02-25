// AES-GCM Testbench
// Verifies the implementation against NIST SP 800-38D test vectors
// Reference: "The Design of a High-Throughput Hardware Architecture for the AES-GCM Algorithm"
//            Table III - NIST Test Patterns
//
// Test Cases from NIST SP 800-38D Appendix B:
//
// TC1: K=0, IV=0, PT=empty, AAD=empty
//   Expected Tag = 58e2fccefa7e3061367f1d57a4e7455a
//
// TC2: K=0, IV=0, PT=0^128, AAD=empty
//   Expected CT  = 0388dace60b6a392f328c2b971b2fe78
//   Expected Tag = ab6e47d42cec13bdf53a67b21257bddf
//
// TC3: K=feffe9928665731c6d6a8f9467308308,
//      IV=cafebabefacedbaddecaf888,
//      PT=4 blocks, AAD=empty
//   Expected CT  = 42831ec221777424...
//   Expected Tag = 4d5c2af327cd64a62cf35abd2ba6fab4

`timescale 1ns/1ps

module aes_gcm_tb;

    // =========================================================================
    // DUT signals
    // =========================================================================
    reg         clk, rst;
    reg  [127:0] key;
    reg  [95:0]  iv;
    reg         start;
    reg  [127:0] aad_data;
    reg         aad_valid, aad_last;
    reg  [127:0] pt_data;
    reg         pt_valid, pt_last;
    wire [127:0] ct_data;
    wire        ct_valid;
    wire [127:0] tag_out;
    wire        tag_valid;

    // =========================================================================
    // DUT
    // =========================================================================
    aes_gcm_top dut (
        .clk(clk), .rst(rst),
        .key(key), .iv(iv), .start(start),
        .aad_data(aad_data), .aad_valid(aad_valid), .aad_last(aad_last),
        .pt_data(pt_data),   .pt_valid(pt_valid),   .pt_last(pt_last),
        .ct_data(ct_data),   .ct_valid(ct_valid),
        .tag_out(tag_out),   .tag_valid(tag_valid)
    );

    // =========================================================================
    // Clock
    // =========================================================================
    initial clk = 0;
    always #5 clk = ~clk;  // 100 MHz

    // =========================================================================
    // Tracking variables
    // =========================================================================
    integer pass_count, fail_count;
    integer tc;

    task check_ct;
        input [127:0] got;
        input [127:0] expected;
        input [127:0] tc_num;
        begin
            if (got === expected) begin
                $display("[TC%0d] CT    PASS: %032h", tc_num, got);
                pass_count = pass_count + 1;
            end else begin
                $display("[TC%0d] CT    FAIL: got=%032h  expected=%032h", tc_num, got, expected);
                fail_count = fail_count + 1;
            end
        end
    endtask

    task check_tag;
        input [127:0] got;
        input [127:0] expected;
        input integer tc_num;
        begin
            if (got === expected) begin
                $display("[TC%0d] TAG   PASS: %032h", tc_num, got);
                pass_count = pass_count + 1;
            end else begin
                $display("[TC%0d] TAG   FAIL: got=%032h  expected=%032h", tc_num, got, expected);
                fail_count = fail_count + 1;
            end
        end
    endtask

    // =========================================================================
    // Helper: reset the DUT
    // =========================================================================
    task do_reset;
        begin
            rst       <= 1;
            start     <= 0;
            aad_valid <= 0; aad_last <= 0;
            pt_valid  <= 0; pt_last  <= 0;
            @(posedge clk); #1;
            @(posedge clk); #1;
            rst <= 0;
            @(posedge clk); #1;
        end
    endtask

    // =========================================================================
    // Helper: send start pulse
    // =========================================================================
    task send_start;
        input [127:0] k;
        input [95:0]  i_v;
        begin
            key   <= k;
            iv    <= i_v;
            start <= 1;
            @(posedge clk); #1;
            start <= 0;
        end
    endtask

    // =========================================================================
    // Helper: send one AAD block
    // =========================================================================
    task send_aad;
        input [127:0] data;
        input         last;
        begin
            // Wait for GHASH to be ready (it may take a few cycles to be ready
            // after start, but that's handled inside the DUT FSM)
            aad_data  <= data;
            aad_valid <= 1;
            aad_last  <= last;
            @(posedge clk); #1;
            aad_valid <= 0;
            aad_last  <= 0;
        end
    endtask

    // =========================================================================
    // Helper: send one PT block, wait for corresponding CT
    // =========================================================================
    reg [127:0] captured_ct [0:15];
    integer ct_idx;

    task send_pt_block;
        input [127:0] data;
        input         last;
        begin
            pt_data  <= data;
            pt_valid <= 1;
            pt_last  <= last;
            @(posedge clk); #1;
            pt_valid <= 0;
            pt_last  <= 0;
        end
    endtask

    // =========================================================================
    // Helper: wait for ct_valid and capture
    // =========================================================================
    task wait_ct;
        output [127:0] ct;
        begin : wait_ct_block
            integer timeout;
            timeout = 0;
            ct = 128'b0;
            while (!ct_valid && timeout < 200) begin
                @(posedge clk); #1;
                timeout = timeout + 1;
            end
            if (ct_valid) begin
                ct = ct_data;
                @(posedge clk); #1;
            end else $display("ERROR: ct_valid timeout");
        end
    endtask

    // =========================================================================
    // Helper: wait for tag_valid
    // =========================================================================
    task wait_tag;
        output [127:0] t;
        begin : wait_tag_block
            integer timeout;
            timeout = 0;
            t = 128'b0;
            while (!tag_valid && timeout < 500) begin
                @(posedge clk); #1;
                timeout = timeout + 1;
            end
            if (tag_valid) t = tag_out;
            else $display("ERROR: tag_valid timeout");
        end
    endtask

    // =========================================================================
    // Main test sequence
    // =========================================================================
    reg [127:0] got_tag, got_ct;
    reg [127:0] exp_ct;

    initial begin
        $dumpfile("aes_gcm_sim.vcd");
        $dumpvars(0, aes_gcm_tb);

        pass_count = 0;
        fail_count = 0;
        rst = 1;
        start = 0;
        aad_valid = 0; aad_last = 0;
        pt_valid  = 0; pt_last  = 0;
        key = 0; iv = 0;
        pt_data = 0; aad_data = 0;

        // Initial reset
        repeat(5) @(posedge clk); #1;
        rst = 0;
        repeat(2) @(posedge clk); #1;

        // =================================================================
        // TEST CASE 1: K=0, IV=0, PT=empty, AAD=empty
        // Expected Tag = 58e2fccefa7e3061367f1d57a4e7455a
        // =================================================================
        $display("");
        $display("========================================");
        $display("TEST CASE 1: Empty PT, Empty AAD");
        $display("========================================");

        send_start(128'h0, 96'h0);

        // No AAD
        // Signal end of PT with pt_last=1, pt_valid=0
        // But first wait for DUT to reach S_PT state (~26 cycles from start)
        repeat(28) @(posedge clk); #1;
        pt_last <= 1;
        @(posedge clk); #1;
        pt_last <= 0;

        wait_tag(got_tag);
        check_tag(got_tag, 128'h58e2fccefa7e3061367f1d57a4e7455a, 1);

        repeat(5) @(posedge clk); #1;

        // =================================================================
        // TEST CASE 2: K=0, IV=0, PT=0^128, AAD=empty
        // Expected CT  = 0388dace60b6a392f328c2b971b2fe78
        // Expected Tag = ab6e47d42cec13bdf53a67b21257bddf
        // =================================================================
        $display("");
        $display("========================================");
        $display("TEST CASE 2: 1 PT block, Empty AAD");
        $display("========================================");

        do_reset;
        send_start(128'h0, 96'h0);

        // Wait for DUT to reach S_PT (~26 cycles)
        repeat(28) @(posedge clk); #1;

        // Send one PT block (all zeros), mark as last
        send_pt_block(128'h0, 1'b1);

        // Capture CT
        wait_ct(got_ct);
        check_ct(got_ct, 128'h0388dace60b6a392f328c2b971b2fe78, 2);

        // Capture tag
        wait_tag(got_tag);
        check_tag(got_tag, 128'hab6e47d42cec13bdf53a67b21257bddf, 2);

        repeat(5) @(posedge clk); #1;

        // =================================================================
        // TEST CASE 3: Standard NIST AES-128-GCM test case
        // K  = feffe9928665731c6d6a8f9467308308
        // IV = cafebabefacedbaddecaf888
        // PT = 4 x 128-bit blocks
        // Expected CT  = 42831ec221777424 4b7221b784d0d49c
        //                e3aa212f2c02a4e0 35c17e2329aca12e
        //                21d514b254669316 7d8f6a5aac84aa05
        //                1ba30b396a0aac97 3d58e091473f5985
        //   (Note: last block only 32 bytes but treated as full block here for simplicity)
        // Expected Tag = 4d5c2af327cd64a62cf35abd2ba6fab4
        // =================================================================
        $display("");
        $display("========================================");
        $display("TEST CASE 3: 4 PT blocks, Empty AAD");
        $display("========================================");

        do_reset;
        send_start(128'hfeffe9928665731c6d6a8f9467308308, 96'hcafebabefacedbaddecaf888);

        // Wait for DUT to reach S_PT
        repeat(28) @(posedge clk); #1;

        // Send 4 PT blocks
        send_pt_block(128'hd9313225f88406e5a55909c5aff5269a, 1'b0);
        send_pt_block(128'h86a7a9531534f7da2e4c303d8a318a72, 1'b0);
        send_pt_block(128'h1c3c0c95956809532fcf0e2449a6b525, 1'b0);
        send_pt_block(128'hb16aedf5aa0de657ba637b391aafd255, 1'b1);

        // Capture 4 CT blocks
        wait_ct(got_ct);
        check_ct(got_ct, 128'h42831ec2217774244b7221b784d0d49c, 3);

        wait_ct(got_ct);
        check_ct(got_ct, 128'he3aa212f2c02a4e035c17e2329aca12e, 3);

        wait_ct(got_ct);
        check_ct(got_ct, 128'h21d514b25466931c7d8f6a5aac84aa05, 3);

        wait_ct(got_ct);
        check_ct(got_ct, 128'h1ba30b396a0aac973d58e091473f5985, 3);

        // Capture tag
        wait_tag(got_tag);
        check_tag(got_tag, 128'h4d5c2af327cd64a62cf35abd2ba6fab4, 3);

        repeat(10) @(posedge clk); #1;

        // =================================================================
        // Summary
        // =================================================================
        $display("");
        $display("========================================");
        $display("SIMULATION COMPLETE");
        $display("PASSED: %0d", pass_count);
        $display("FAILED: %0d", fail_count);
        $display("========================================");

        if (fail_count == 0)
            $display("ALL TESTS PASSED");
        else
            $display("SOME TESTS FAILED - check output above");

        $finish;
    end

    // Safety timeout
    initial begin
        #1000000;
        $display("SIMULATION TIMEOUT");
        $finish;
    end

endmodule
