# Makefile

all: mtud_prober mtud_destination

mtud_prober: mtud_prober.c
	gcc -o mtud_prober mtud_prober.c -lpthread

mtud_destination: mtud_destination.c
	gcc -o mtud_destination mtud_destination.c

clean:
	rm -f mtud_prober mtud_destination *.txt
