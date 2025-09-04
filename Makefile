CC = gcc 
TARGET = babyfs 
SRC = babyfs.c 
all: clean $(TARGET) 
$(TARGET): 
	$(CC) $(SRC) -o $(TARGET) `pkg-config fuse3 --cflags --libs` 
	./babyfs /tmp/mnt --lower="/mnt/c/Users/sudhi/OneDrive/Desktop/Experiments/Filesystem/lower" --upper="/mnt/c/Users/sudhi/OneDrive/Desktop/Experiments/Filesystem/upper"

clean: 
	rm -f $(TARGET) 
	fusermount3 -u /tmp/mnt

logs: 
	tail -f /var/logs/syslog