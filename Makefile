
CC := gcc

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -g -O2

TARGET := build/fanotify_monitor
SOURCE := src/monitor/fanotify_monitor.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)

clean:
	rm -rf build

