# Makefile

MAIN=main
CC=gcc
OUTPATH=./HMAC
OUTPATH1=./coap
INCPATH=./HMAC/inc
SRCPATH=./HMAC/scr
source=$(wildcard $(SRCPATH)/*.c)
source1=$(wildcard $(OUTPATH1)/*.c)
obj1=$(patsubst %.c,$(OUTPATH1)/%.o,$(notdir $(source1)))
obj2=$(patsubst %.c,$(OUTPATH)/%.o,$(notdir $(source)))

$(MAIN): $(obj1) $(obj2)
	$(CC) $^ -o $@ -I $(INCPATH)

$(OUTPATH1)/%.o: $(OUTPATH1)/%.c
	$(CC) -c $< -o $@ -I $(INCPATH)

$(OUTPATH)/%.o: $(SRCPATH)/%.c
	$(CC) -c $< -o $@ -I $(INCPATH)

.PHONY: clean
clean:
	rm -rf *.o $(MAIN) $(OUTPATH)/*.o $(OUTPATH1)/*.o
