MAIN=main
CC=gcc
OUTPATH=./HMAC
INCPATH=./HMAC/inc
SRCPATH=./HMAC/scr
source=$(wildcard $(SRCPATH)/*.c)
source1=$(wildcard ./*.c)
obj1=$(patsubst %.c,%.o,$(notdir $(source1)))
obj2=$(patsubst %.c,$(OUTPATH)/%.o,$(notdir $(source)))

$(MAIN):$(obj1) $(obj2)
	$(CC) $^ -o $@ -I $(INCPATH)
./HMAC/%.o:$(SRCPATH)/%.c
	$(CC) -c $< -o $@ -I $(INCPATH)
./%.o:./%.c
	$(CC) -c $< -o $@ -I $(INCPATH)

.PHONY: clean
clean:
	rm -rf *.o $(MAIN) $(OUTPATH)/*.o
