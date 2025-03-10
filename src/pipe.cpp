#include "libzdb/pipe.hpp"
#include <fcntl.h>
#include <libzdb/error.hpp>
#include <unistd.h>
#include <utility>

zdb::Pipe::Pipe(bool close_on_exec) {
    if (pipe2(fds_, close_on_exec ? O_CLOEXEC : 0) < 0) {
        zdb::Error::send_errno("Pipe creation failed");
    }
}

zdb::Pipe::~Pipe() {
    close_read();
    close_write();
}

int zdb::Pipe::release_read() {
    return std::exchange(fds_[read_fd], -1);
}

int zdb::Pipe::release_write() {
    return std::exchange(fds_[write_fd], -1);
}

void zdb::Pipe::close_read() {
    if (fds_[read_fd] != -1) {
        close(fds_[read_fd]);
        fds_[read_fd] = -1;
    }
}

void zdb::Pipe::close_write() {
    if (fds_[write_fd] != -1) {
        close(fds_[write_fd]);
        fds_[write_fd] = -1;
    }
}

std::vector<std::byte> zdb::Pipe::read() {
    char buffer[1024];
    ssize_t bytes_read = ::read(fds_[read_fd], buffer, sizeof(buffer));
    if (bytes_read < 0) {
        zdb::Error::send_errno("Pipe read failed");
    }
    printf("Pipe read: %s\n", buffer);
    auto bytes = reinterpret_cast<std::byte *>(buffer);
    return std::vector<std::byte>(bytes, bytes + bytes_read);
}

void zdb::Pipe::write(std::byte *from, std::size_t bytes) {
    ssize_t bytes_written = ::write(fds_[write_fd], from, bytes);
    if (bytes_written < 0) {
        zdb::Error::send_errno("Pipe write failed");
    }
}
