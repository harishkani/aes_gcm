RTL_DIR = rtl
TB_DIR  = tb

SRCS = $(RTL_DIR)/aes_sbox.v \
       $(RTL_DIR)/aes_key_expand.v \
       $(RTL_DIR)/aes_encrypt.v \
       $(RTL_DIR)/gf_mult128.v \
       $(RTL_DIR)/ghash.v \
       $(RTL_DIR)/aes_gcm_top.v \
       $(TB_DIR)/aes_gcm_tb.v

SIM_BIN = aes_gcm_sim

.PHONY: all sim clean

all: sim

sim: $(SRCS)
	iverilog -o $(SIM_BIN) -Wall -Wno-timescale $(SRCS) && \
	vvp $(SIM_BIN)

clean:
	rm -f $(SIM_BIN) aes_gcm_sim.vcd
