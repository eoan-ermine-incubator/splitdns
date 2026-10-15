#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

constexpr std::string_view kModule = "mymodule";
const fs::path kConfig = "/etc/nsswitch.conf";
const fs::path kBackup = "/etc/nsswitch.conf.bak";

[[noreturn]] void throwSystemError(const std::string& operation) {
    throw std::system_error(
        errno, std::generic_category(), operation
    );
}

std::string readFile(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot read " + path.string());
    }

    std::string contents{
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    };

    if (file.bad()) {
        throw std::runtime_error("Failed while reading " + path.string());
    }

    return contents;
}

std::string_view trim(std::string_view text) {
    constexpr std::string_view whitespace = " \t\r\n";

    const auto first = text.find_first_not_of(whitespace);
    if (first == std::string_view::npos) {
        return {};
    }

    return text.substr(
        first,
        text.find_last_not_of(whitespace) - first + 1
    );
}

struct Token {
    std::string_view value;
    std::size_t end;
};

std::vector<Token> tokenize(std::string_view text) {
    std::vector<Token> tokens;

    std::size_t pos = 0;

    while (pos < text.size()) {
        pos = text.find_first_not_of(" \t\r", pos);

        if (pos == std::string_view::npos) {
            break;
        }

        const auto end = text.find_first_of(" \t\r", pos);
        const auto tokenEnd =
            end == std::string_view::npos ? text.size() : end;

        tokens.push_back({
            text.substr(pos, tokenEnd - pos),
            tokenEnd
        });

        pos = tokenEnd;
    }

    return tokens;
}

bool isAction(std::string_view token) {
    return token.size() >= 2 &&
           token.front() == '[' &&
           token.back() == ']';
}

// Returns true if this is a hosts entry.
// Modifies the line only when the module is not already configured.
bool updateHostsLine(std::string& line) {
    const std::string_view view(line);

    // Ignore comments and identify the database name.
    const auto first = view.find_first_not_of(" \t\r");

    if (first == std::string_view::npos ||
        view[first] == '#') {
        return false;
    }

    const auto comment = view.find('#', first);
    const auto end = comment == std::string_view::npos
        ? view.size()
        : comment;

    const auto colon = view.find(':', first);

    if (colon == std::string_view::npos || colon >= end) {
        return false;
    }

    if (trim(view.substr(first, colon - first)) != "hosts") {
        return false;
    }

    const auto services = view.substr(colon + 1, end - colon - 1);
    const auto tokens = tokenize(services);

    // An exact token match prevents duplicate insertion.
    for (const auto& token : tokens) {
        if (token.value == kModule) {
            return true;
        }
    }

    // Prefer inserting after files and any action clauses
    // belonging to that service.
    std::size_t insertion = colon + 1;

    const auto files = std::find_if(
        tokens.begin(),
        tokens.end(),
        [](const Token& token) {
            return token.value == "files";
        }
    );

    if (files != tokens.end()) {
        insertion = colon + 1 + files->end;

        auto next = std::next(files);

        while (next != tokens.end() && isAction(next->value)) {
            insertion = colon + 1 + next->end;
            ++next;
        }
    }

    line.insert(insertion, " " + std::string(kModule));
    return true;
}

std::string updateConfiguration(const std::string& contents) {
    std::string result;
    result.reserve(contents.size() + kModule.size() + 16);

    bool foundHosts = false;
    std::size_t start = 0;

    while (start < contents.size()) {
        const auto newline = contents.find('\n', start);
        const bool hasNewline = newline != std::string::npos;

        const auto end = hasNewline ? newline : contents.size();

        std::string line = contents.substr(start, end - start);

        foundHosts = updateHostsLine(line) || foundHosts;

        result += line;

        if (hasNewline) {
            result += '\n';
        }

        if (!hasNewline) {
            break;
        }

        start = newline + 1;
    }

    if (!foundHosts) {
        throw std::runtime_error(
            "No hosts entry found in NSS configuration"
        );
    }

    return result;
}

// Write a new file in the same directory, then atomically replace
// the target. Preserve its owner, group, and permission bits.
void atomicReplace(const fs::path& target,
                   const std::string& contents) {
    struct stat metadata {};

    if (::lstat(target.c_str(), &metadata) == -1) {
        throwSystemError("Cannot inspect " + target.string());
    }

    if (!S_ISREG(metadata.st_mode)) {
        throw std::runtime_error(
            "Configuration must be a regular file, not a symlink"
        );
    }

    std::string pattern = target.string() + ".tmp.XXXXXX";
    std::vector<char> name(pattern.begin(), pattern.end());
    name.push_back('\0');

    const int fd = ::mkstemp(name.data());

    if (fd == -1) {
        throwSystemError("Cannot create temporary configuration");
    }

    const fs::path temporary(name.data());
    bool renamed = false;

    try {
        if (::fchown(fd, metadata.st_uid, metadata.st_gid) == -1) {
            throwSystemError("Cannot preserve file ownership");
        }

        if (::fchmod(fd, metadata.st_mode & 07777) == -1) {
            throwSystemError("Cannot preserve file permissions");
        }

        std::size_t written = 0;

        while (written < contents.size()) {
            const auto count = ::write(
                fd,
                contents.data() + written,
                contents.size() - written
            );

            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throwSystemError("Cannot write temporary configuration");
            }

            if (count == 0) {
                throw std::runtime_error("Short write to temporary file");
            }

            written += static_cast<std::size_t>(count);
        }

        if (::fsync(fd) == -1) {
            throwSystemError("Cannot sync temporary configuration");
        }

        if (::close(fd) == -1) {
            throwSystemError("Cannot close temporary configuration");
        }

        if (::rename(temporary.c_str(), target.c_str()) == -1) {
            throwSystemError("Cannot replace configuration");
        }

        renamed = true;
    } catch (...) {
        // If close itself failed, closing again is harmless to attempt
        // here only before a successful rename.
        ::close(fd);

        if (!renamed) {
            ::unlink(temporary.c_str());
        }

        throw;
    }
}

} // namespace

int main() {
    try {
        if (!fs::exists(kConfig)) {
            throw std::runtime_error(
                "NSS configuration file not found: " + kConfig.string()
            );
        }

        // Preserve the original file before making any changes.
        if (!fs::exists(kBackup)) {
            fs::copy_file(
                kConfig,
                kBackup,
                fs::copy_options::none
            );
        }

        const std::string original = readFile(kConfig);
        const std::string updated = updateConfiguration(original);

        if (updated == original) {
            std::cout << "NSS module '" << kModule
                      << "' is already configured\n";
            return 0;
        }

        atomicReplace(kConfig, updated);

        std::cout << "NSS module '" << kModule
                  << "' configured successfully\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
