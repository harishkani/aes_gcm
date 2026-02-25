// =============================================================================
// gf128_mult.v  –  GF(2^128) multiplier for AES-GCM GHASH
//
// Implements the GHASH field multiplication defined in NIST SP 800-38D.
//
// Bit/polynomial convention (as per GCM spec):
//   The leftmost bit of each block is the coefficient of x^0 (lowest degree).
//   In our 128-bit vector this means:
//     bit[127] = x^0  coefficient
//     bit[0]   = x^127 coefficient
//
// Reduction polynomial: x^128 + x^7 + x^2 + x + 1
//   → in our bit ordering the reduction constant is 0xe1 << 120
//     i.e., 128'he1000000000000000000000000000000
//
// Algorithm: schoolbook shift-and-add, 128 iterations (fully unrolled
// as a for-loop inside always@(*) – purely combinational).
//
// Inputs:   A, B  [127:0]
// Output:   Z     [127:0]   Z = A * B in GF(2^128)
// =============================================================================
module gf128_mult (
    input  [127:0] A,
    input  [127:0] B,
    output [127:0] Z
);

reg [127:0] z_r;
reg [127:0] v;
integer     gi;

assign Z = z_r;

// GCM-polynomial reduction constant (x^7 + x^2 + x + 1 in GCM bit ordering)
localparam [127:0] R = 128'he1000000000000000000000000000000;

always @(*) begin : GF_MULT
    v   = B;
    z_r = 128'h0;

    // Iterate from GCM bit 0 (Verilog bit 127) to GCM bit 127 (Verilog bit 0)
    for (gi = 127; gi >= 0; gi = gi - 1) begin
        if (A[gi])
            z_r = z_r ^ v;
        // "multiply v by x" with reduction
        if (v[0])       // LSbit set → degree-127 overflows at next shift
            v = (v >> 1) ^ R;
        else
            v = v >> 1;
    end
end

endmodule
