CONTIKI = ../

CONTIKI_PROJECT = app
DISTDIR = dtn
BACKUPDIR = ~/.backup
NOW=$(shell date +%Y%m%d-%H%M%S)

.PHONY: backup
backup:
	[ -d $(BACKUPDIR) ] || mkdir $(BACKUPDIR)
	rm -rf $(BACKUPDIR)/$(DISTDIR)
	mkdir $(BACKUPDIR)/$(DISTDIR)
	cp Makefile *.c *.h $(BACKUPDIR)/$(DISTDIR)/
	cd $(BACKUPDIR) && tar czf $(DISTDIR)-$(NOW).tar.gz $(DISTDIR)
	rm -rf $(BACKUPDIR)/$(DISTDIR)

all: backup $(CONTIKI_PROJECT)

CONTIKI_SOURCEFILES += dtn.c

include $(CONTIKI)/Makefile.include
