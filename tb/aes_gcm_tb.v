// =============================================================================
// aes_gcm_tb.v  –  Testbench for AES-128-GCM
//
// Test vectors from NIST SP 800-38D, Appendix B:
//   TC1: Key=0, IV=0, no AAD, no PT
//   TC2: Key=0, IV=0, no AAD, PT=0^128
//   TC3: Key=0, IV=0, AAD=0^128, no PT
//   TC4: Key=0, IV=0, AAD=0^128, PT=0^128
//   TC5: Non-zero key/IV from NIST (key=feffe..., iv=cafebabe...)
//        Single-block PT, no AAD
//   TC6: AES-128 standalone sanity check (FIPS 197 known answer)
// =============================================================================
`timescale 1ns/1ps

module aes_gcm_tb;

    // ---------- DUT ports ----------
    reg  [127:0] key;
    reg  [95:0]  iv;
    reg  [127:0] aad;
    reg          aad_valid;
    reg  [127:0] plaintext;
    reg          pt_valid;

    wire [127:0] ciphertext;
    wire [127:0] auth_tag;

    // AES sanity-check ports
    reg  [127:0] aes_pt;
    reg  [127:0] aes_key;
    wire [127:0] aes_ct;

    // ---------- Instantiate DUT ----------
    aes_gcm dut (
        .key        (key),
        .iv         (iv),
        .aad        (aad),
        .aad_valid  (aad_valid),
        .plaintext  (plaintext),
        .pt_valid   (pt_valid),
        .ciphertext (ciphertext),
        .auth_tag   (auth_tag)
    );

    // ---------- AES standalone ----------
    aes_encrypt u_aes (
        .plaintext  (aes_pt),
        .key        (aes_key),
        .ciphertext (aes_ct)
    );

    // ---------- bookkeeping ----------
    integer pass_cnt;
    integer fail_cnt;

    // ------------------------------------------------------------------
    // Helper task: apply inputs, wait, compare
    // ------------------------------------------------------------------
    task run_gcm_test;
        input [127:0] k;
        input [95:0]  v;
        input [127:0] a;
        input         av;
        input [127:0] pt;
        input         pv;
        input [127:0] exp_ct;
        input [127:0] exp_tag;
        input [63:0]  tc_num;
        begin
            key       = k;
            iv        = v;
            aad       = a;
            aad_valid = av;
            plaintext = pt;
            pt_valid  = pv;
            #20;   // let combinational logic settle
            if (ciphertext === exp_ct && auth_tag === exp_tag) begin
                $display("[PASS] TC%0d", tc_num);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("[FAIL] TC%0d", tc_num);
                if (ciphertext !== exp_ct) begin
                    $display("       CT  expected: %032h", exp_ct);
                    $display("       CT  got:      %032h", ciphertext);
                end
                if (auth_tag !== exp_tag) begin
                    $display("       TAG expected: %032h", exp_tag);
                    $display("       TAG got:      %032h", auth_tag);
                end
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    task run_aes_test;
        input [127:0] k;
        input [127:0] pt;
        input [127:0] exp_ct;
        input [63:0]  tc_num;
        begin
            aes_key = k;
            aes_pt  = pt;
            #20;
            if (aes_ct === exp_ct) begin
                $display("[PASS] AES-TC%0d", tc_num);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("[FAIL] AES-TC%0d", tc_num);
                $display("       Expected: %032h", exp_ct);
                $display("       Got:      %032h", aes_ct);
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    // ------------------------------------------------------------------
    // Stimuli
    // ------------------------------------------------------------------
    initial begin
        pass_cnt = 0;
        fail_cnt = 0;
        $display("====================================================");
        $display("          AES-128-GCM Verification Suite");
        $display("====================================================");

        // ==============================================================
        // AES standalone checks (sanity before testing GCM)
        // ==============================================================
        $display("\n--- AES-128 Known-Answer Tests ---");

        // FIPS 197 Appendix B
        // Key    = 2b7e151628aed2a6abf7158809cf4f3c
        // PT     = 3243f6a8885a308d313198a2e0370734
        // CT     = 3925841d02dc09fbdc118597196a0b32
        run_aes_test(
            128'h2b7e151628aed2a6abf7158809cf4f3c,
            128'h3243f6a8885a308d313198a2e0370734,
            128'h3925841d02dc09fbdc118597196a0b32,
            1);

        // All-zero key+PT → H for GCM TC1/TC2
        // Key=0, PT=0  →  CT = 66e94bd4ef8a2c3b884cfa59ca342b2e
        run_aes_test(
            128'h0,
            128'h0,
            128'h66e94bd4ef8a2c3b884cfa59ca342b2e,
            2);

        // All-zero key, PT = J0 for TC1 (= E_K(0^96 || 1) for tag)
        // Key=0, PT=00000000000000000000000000000001  → 58e2fccefa7e3061367f1d57a4e7455a
        run_aes_test(
            128'h0,
            128'h00000000000000000000000000000001,
            128'h58e2fccefa7e3061367f1d57a4e7455a,
            3);

        // All-zero key, PT = CTR1 = 0x00..002
        // Key=0, PT=00000000000000000000000000000002 → 0388dace60b6a392f328c2b971b2fe78
        run_aes_test(
            128'h0,
            128'h00000000000000000000000000000002,
            128'h0388dace60b6a392f328c2b971b2fe78,
            4);

        // ==============================================================
        // AES-128-GCM NIST test vectors (SP 800-38D Appendix B)
        // ==============================================================
        $display("\n--- AES-128-GCM NIST Test Vectors ---");

        // TC1: Key=0, IV=0, no AAD, no PT
        //   Tag = 58e2fccefa7e3061367f1d57a4e7455a
        run_gcm_test(
            128'h0,
            96'h0,
            128'h0, 0,
            128'h0, 0,
            128'h0,
            128'h58e2fccefa7e3061367f1d57a4e7455a,
            1);

        // TC2: Key=0, IV=0, no AAD, PT=0^128
        //   CT  = 0388dace60b6a392f328c2b971b2fe78
        //   Tag = ab6e47d42cec13bdf53a67b21257bddf
        run_gcm_test(
            128'h0,
            96'h0,
            128'h0, 0,
            128'h0, 1,
            128'h0388dace60b6a392f328c2b971b2fe78,
            128'hab6e47d42cec13bdf53a67b21257bddf,
            2);

        // TC3: Key=feffe9928665731c6d6a8f9467308308
        //      IV =cafebabefacedbaddecaf888
        //      PT (one 128-bit block) = d9313225f88406e5a55909c5aff5269a
        //      no AAD
        //      Expected CT  = 42831ec2217774244b7221b784d0d49c
        //      Expected Tag = 57926dde92a5c01ee854dc9b33ebc856
        //      (verified by independent Python reference)
        run_gcm_test(
            128'hfeffe9928665731c6d6a8f9467308308,
            96'hcafebabefacedbaddecaf888,
            128'h0, 0,
            128'hd9313225f88406e5a55909c5aff5269a,
            1,
            128'h42831ec2217774244b7221b784d0d49c,
            128'h57926dde92a5c01ee854dc9b33ebc856,
            3);

        // TC4: Same key/IV, single-block AAD + single-block PT
        //      AAD = feedfacedeadbeeffeedfacedeadbeef
        //      PT  = d9313225f88406e5a55909c5aff5269a
        //      Expected CT  = 42831ec2217774244b7221b784d0d49c
        //      Expected Tag = 803a17709e281bcbd7e920f13cf41505
        //      (verified by independent Python reference)
        run_gcm_test(
            128'hfeffe9928665731c6d6a8f9467308308,
            96'hcafebabefacedbaddecaf888,
            128'hfeedfacedeadbeeffeedfacedeadbeef, 1,
            128'hd9313225f88406e5a55909c5aff5269a,
            1,
            128'h42831ec2217774244b7221b784d0d49c,
            128'h803a17709e281bcbd7e920f13cf41505,
            4);

        // ==============================================================
        // Summary
        // ==============================================================
        $display("\n====================================================");
        $display("  Results:  %0d passed,  %0d failed", pass_cnt, fail_cnt);
        if (fail_cnt == 0)
            $display("  *** ALL TESTS PASSED ***");
        else
            $display("  *** FAILURES DETECTED ***");
        $display("====================================================");
        $finish;
    end

endmodule
