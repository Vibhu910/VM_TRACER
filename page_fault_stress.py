import mmap
import time
import os

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")  # usually 4096 bytes
SIZE = 16 * 1024 * 1024                 # 16 MB per mapping
ITERATIONS = 200                        # repeat count


def main() -> None:
    for _ in range(ITERATIONS):
        # Anonymous mapping; not backed by a file.
        m = mmap.mmap(-1, SIZE)
        # Touch one byte per page to force a page fault on each page.
        for i in range(0, SIZE, PAGE_SIZE):
            m[i] = 1
        m.close()

    # Give vm_tracer a moment to drain any remaining events.
    time.sleep(1)


if __name__ == "__main__":
    main()

