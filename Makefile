vmlinux:
	@echo "Checking vmlinux.h..."
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		if [ -f /sys/kernel/btf/vmlinux ]; then \
			bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
		else \
			echo "Error: BTF not available. Are you running this in the VM?"; \
			exit 1; \
		fi \
	else \
		echo "vmlinux.h already exists, skipping generation"; \
	fi