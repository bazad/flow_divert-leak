TARGET = flow_divert-leak

ARCH    ?= x86_64
SDK     ?= macosx

ifneq ($(ARCH),x86_64)
CLANG    := $(shell xcrun --sdk $(SDK) --find clang)
ifeq ($(CLANG),)
$(error Could not find clang for SDK $(SDK))
endif
SYSROOT  := $(shell xcrun --sdk $(SDK) --show-sdk-path)
CC       := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)
endif
CODESIGN := codesign

CFLAGS = -O2 -Wall -Werror -Wpedantic -Wno-gnu

FRAMEWORKS = -framework Foundation -framework IOKit

SOURCES = $(TARGET).c

HEADERS =

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(DEFINES) -o $@ $(SOURCES)
	$(CODESIGN) -s - $@

clean:
	rm -f -- $(TARGET)
