CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

COMMON_OBJS = common.o kmm_mock.o paillier_host.o
DEMO_OBJS = main_demo.o $(COMMON_OBJS)
BENCH_OBJS = main_bench.o $(COMMON_OBJS)
DELEGATE_DEMO_OBJS = main_delegate_demo.o $(COMMON_OBJS)
PAILLIER_REF_OBJS = main_paillier_ref.o paillier_host.o
PAILLIER_BENCH_OBJS = main_paillier_bench.o paillier_host.o
PAILLIER_TA_DEMO_OBJS = main_paillier_ta_demo.o $(COMMON_OBJS)
FULL_CRYPTO_DEMO_OBJS = main_full_crypto_demo.o $(COMMON_OBJS)
FULL_CRYPTO_VERIFY_OBJS = main_full_crypto_verify.o $(COMMON_OBJS)
FULL_CRYPTO_BENCH_OBJS = main_full_crypto_bench.o $(COMMON_OBJS)

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include
#Add/link other required libraries here
LDADD += -lteec -lcrypto -L$(TEEC_EXPORT)/lib
LDADD_CRYPTO += -lcrypto -L$(TEEC_EXPORT)/lib

BINARIES = secure_iiot_demo secure_iiot_bench secure_iiot_delegate_demo \
	   secure_iiot_paillier_ref secure_iiot_paillier_bench \
	   secure_iiot_paillier_ta_demo secure_iiot_full_crypto_demo \
	   secure_iiot_full_crypto_verify secure_iiot_full_crypto_bench \
	   secure_iiot

.PHONY: all
all: $(BINARIES)

secure_iiot_demo: $(DEMO_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(DEMO_OBJS) $(LDADD)

secure_iiot_bench: $(BENCH_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(BENCH_OBJS) $(LDADD)

secure_iiot_delegate_demo: $(DELEGATE_DEMO_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(DELEGATE_DEMO_OBJS) $(LDADD)

secure_iiot_paillier_ref: $(PAILLIER_REF_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(PAILLIER_REF_OBJS) $(LDADD_CRYPTO)

secure_iiot_paillier_bench: $(PAILLIER_BENCH_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(PAILLIER_BENCH_OBJS) $(LDADD_CRYPTO)

secure_iiot_paillier_ta_demo: $(PAILLIER_TA_DEMO_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(PAILLIER_TA_DEMO_OBJS) $(LDADD)

secure_iiot_full_crypto_demo: $(FULL_CRYPTO_DEMO_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(FULL_CRYPTO_DEMO_OBJS) $(LDADD)

secure_iiot_full_crypto_verify: $(FULL_CRYPTO_VERIFY_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(FULL_CRYPTO_VERIFY_OBJS) $(LDADD)

secure_iiot_full_crypto_bench: $(FULL_CRYPTO_BENCH_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(FULL_CRYPTO_BENCH_OBJS) $(LDADD)

secure_iiot: secure_iiot_demo
	cp secure_iiot_demo secure_iiot

.PHONY: clean
clean:
	rm -f $(COMMON_OBJS) main_demo.o main_bench.o main_delegate_demo.o \
		main_paillier_ref.o main_paillier_bench.o \
		main_paillier_ta_demo.o main_full_crypto_demo.o \
		main_full_crypto_verify.o main_full_crypto_bench.o \
		$(BINARIES)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
