CXX      := g++
TARGET   := nshmemlock
SRC      := nshmemlock.cpp

CXXFLAGS := -std=c++17 -O3 -march=native -flto
LDFLAGS  :=
LIBS     := 

# Detect Alpine Linux (musl)
ifeq ($(wildcard /etc/alpine-release),)
    # Normal Linux (glibc) dynamic link
    $(info Building with dynamic linking (glibc))
else
    # Alpine Linux (musl) static link
    $(info Building with static linking (Alpine/musl))
    LDFLAGS += -static
endif

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< $(LIBS) -o $@

clean:
	rm -f $(TARGET)
