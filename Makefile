# define the C compiler to use
CPP = g++

# define any compile-time flags
CPPFLAGS = -Wall -g -std=c++17 -pthread

# define any directories containing header files other than /usr/include
INCLUDES = -I./include

# define library paths in addition to /usr/lib
LFLAGS =

# define any libraries to link into executable:
LIBS = -lcryptopp -lmbedcrypto

# define src and obj directories
SRC_DIR = src

# define build directory
OBJ_DIR = build

# define the C source files
SRCS = $(wildcard $(SRC_DIR)/*.cpp)

# define the C object files 
OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

# define the executable file 
MAIN = mitemp

###############
### targets ###
###############

.PHONY: build clean install

all: build $(MAIN)

build:
	-@ mkdir -p $(OBJ_DIR)

$(MAIN): $(OBJS) 
	$(CPP) $(CPPFLAGS) $(INCLUDES) -o $(OBJ_DIR)/$(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CPP) $(CPPFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	-@ $(RM) $(OBJS) $(OBJ_DIR)/$(MAIN) *~

# define install directories
ifeq ($(PREFIX),)
  PREFIX = /usr/local
endif

install: all
	install -d $(DESTDIR)$(PREFIX)/bin/ 
	install -m 755 $(OBJ_DIR)/$(MAIN) $(DESTDIR)$(PREFIX)/bin/
