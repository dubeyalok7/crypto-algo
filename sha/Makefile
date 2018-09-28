SUBDIRS = $(shell ls -d */)
all:
	for dir in $(SUBDIRS) ; do \
		make -C  $$dir ; \
		done
clean:
	for dir in $(SUBDIRS) ; do \
		cd $$dir ; \
		make clean; \
		cd ..; \
		done
