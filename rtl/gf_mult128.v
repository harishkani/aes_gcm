// GF(2^128) Multiplier - 4th-order Karatsuba with 3-stage pipeline
// Based on: "The Design of a High-Throughput Hardware Architecture for the AES-GCM Algorithm"
//
// GCM field: GF(2^128) with irreducible polynomial x^128 + x^7 + x^2 + x + 1
//
// Bit-ordering note (NIST SP 800-38D §6.3):
//   In GCM, a 128-bit block [127:0] has bit [127] = coefficient of x^0
//   and bit [0] = coefficient of x^127 (reversed vs standard polynomial).
//   To use standard Karatsuba carry-less multiply (where bit[i]=coeff(x^i)):
//     1. Bit-reverse both operands before Karatsuba
//     2. Reduce with x^128 + x^7 + x^2 + x + 1
//     3. Bit-reverse the result
//   This gives the correct GCM GF(2^128) product.
//
// Pipeline stages (paper Fig. 2):
//   Stage 1: capture/reverse inputs, compute base (16x16) products
//   Stage 2: combine to (64x64) level → pipeline reg
//   Stage 3: full (128x128) product + reduce + re-reverse → output reg

module gf_mult128 (
    input         clk,
    input         rst,
    input  [127:0] A,           // GCM-encoded operand
    input  [127:0] B,           // GCM-encoded operand
    input         valid_in,
    output reg [127:0] result,  // GCM-encoded product
    output reg    valid_out
);

    // -----------------------------------------------------------------------
    // Bit reversal
    // -----------------------------------------------------------------------
    function [127:0] bit_rev128;
        input [127:0] x;
        integer k;
        begin
            for (k = 0; k < 128; k = k + 1)
                bit_rev128[k] = x[127-k];
        end
    endfunction

    // -----------------------------------------------------------------------
    // Carry-less (GF(2)) polynomial multiplication functions
    // bit[i] = coefficient of x^i  (standard, after bit-reversal)
    // -----------------------------------------------------------------------
    function [14:0] clmul8;
        input [7:0] a, b;
        reg [14:0] p; reg [14:0] t; integer j;
        begin p=15'b0; t={7'b0,a};
            for(j=0;j<8;j=j+1) begin if(b[j]) p=p^t; t=t<<1; end clmul8=p; end
    endfunction
    function [30:0] clmul16;
        input [15:0] a, b; reg [14:0] z0,z2,z1;
        begin z0=clmul8(a[7:0],b[7:0]); z2=clmul8(a[15:8],b[15:8]);
              z1=clmul8(a[7:0]^a[15:8],b[7:0]^b[15:8]);
              clmul16=({16'b0,z2}<<16)^({16'b0,z1^z0^z2}<<8)^{16'b0,z0}; end
    endfunction
    function [62:0] clmul32;
        input [31:0] a, b; reg [30:0] z0,z2,z1;
        begin z0=clmul16(a[15:0],b[15:0]); z2=clmul16(a[31:16],b[31:16]);
              z1=clmul16(a[15:0]^a[31:16],b[15:0]^b[31:16]);
              clmul32=({32'b0,z2}<<32)^({32'b0,z1^z0^z2}<<16)^{32'b0,z0}; end
    endfunction
    function [126:0] clmul64;
        input [63:0] a, b; reg [62:0] z0,z2,z1;
        begin z0=clmul32(a[31:0],b[31:0]); z2=clmul32(a[63:32],b[63:32]);
              z1=clmul32(a[31:0]^a[63:32],b[31:0]^b[63:32]);
              clmul64=({64'b0,z2}<<64)^({64'b0,z1^z0^z2}<<32)^{64'b0,z0}; end
    endfunction
    function [254:0] clmul128;
        input [127:0] a, b; reg [126:0] z0,z2,z1;
        begin z0=clmul64(a[63:0],b[63:0]); z2=clmul64(a[127:64],b[127:64]);
              z1=clmul64(a[63:0]^a[127:64],b[63:0]^b[127:64]);
              clmul128=({128'b0,z2}<<128)^({128'b0,z1^z0^z2}<<64)^{128'b0,z0}; end
    endfunction

    // Reduce 255-bit poly mod x^128 + x^7 + x^2 + x + 1
    function [127:0] gf_reduce;
        input [254:0] p; reg [254:0] tmp; integer j;
        begin tmp=p;
            for(j=254;j>=128;j=j-1) begin
                if(tmp[j]) begin
                    tmp[j-121]=tmp[j-121]^1'b1; tmp[j-126]=tmp[j-126]^1'b1;
                    tmp[j-127]=tmp[j-127]^1'b1; tmp[j-128]=tmp[j-128]^1'b1;
                    tmp[j]=1'b0;
                end
            end gf_reduce=tmp[127:0]; end
    endfunction

    // GCM-correct GF(2^128) multiply:
    // bit-reverse inputs, standard Karatsuba+reduce, bit-reverse output
    function [127:0] gf_mult_gcm;
        input [127:0] a, b;
        reg [127:0] ar, br, cr;
        begin
            ar = bit_rev128(a);
            br = bit_rev128(b);
            cr = gf_reduce(clmul128(ar, br));
            gf_mult_gcm = bit_rev128(cr);
        end
    endfunction

    // -----------------------------------------------------------------------
    // 3-Stage Pipeline (captures paper's pipeline register placement)
    // Stage 1: bit-reverse inputs, compute 64x64 level products
    // Stage 2: capture 64x64 results
    // Stage 3: combine → reduce → bit-reverse → output
    // -----------------------------------------------------------------------
    reg [127:0] s1_Ar, s1_Br;
    reg         s1_vld;

    wire [126:0] s1_z0 = clmul64(s1_Ar[63:0],   s1_Br[63:0]);
    wire [126:0] s1_z2 = clmul64(s1_Ar[127:64],  s1_Br[127:64]);
    wire [126:0] s1_z1 = clmul64(s1_Ar[63:0] ^ s1_Ar[127:64],
                                  s1_Br[63:0] ^ s1_Br[127:64]);

    // Stage 1 register
    always @(posedge clk) begin
        if (rst) begin
            s1_Ar  <= 128'b0; s1_Br  <= 128'b0; s1_vld <= 1'b0;
        end else begin
            s1_Ar  <= bit_rev128(A);
            s1_Br  <= bit_rev128(B);
            s1_vld <= valid_in;
        end
    end

    reg [126:0] s2_z0, s2_z2, s2_z1;
    reg         s2_vld;

    // Stage 2 register (captures 64x64 products)
    always @(posedge clk) begin
        if (rst) begin
            s2_z0 <= 127'b0; s2_z2 <= 127'b0; s2_z1 <= 127'b0; s2_vld <= 1'b0;
        end else begin
            s2_z0 <= s1_z0; s2_z2 <= s1_z2; s2_z1 <= s1_z1; s2_vld <= s1_vld;
        end
    end

    // Combine to 255-bit product (combinatorial)
    wire [254:0] s2_product = ({128'b0, s2_z2} << 128) ^
                               ({128'b0, s2_z1 ^ s2_z0 ^ s2_z2} << 64) ^
                               {128'b0, s2_z0};

    // Stage 3: reduce + bit-reverse output
    always @(posedge clk) begin
        if (rst) begin
            result    <= 128'b0;
            valid_out <= 1'b0;
        end else begin
            result    <= bit_rev128(gf_reduce(s2_product));
            valid_out <= s2_vld;
        end
    end

endmodule
