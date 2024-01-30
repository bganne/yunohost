IMAGE=debian-12-generic-amd64.qcow2
URL=https://cdimage.debian.org/cdimage/cloud/bookworm/latest
LOCALHOST=127.1.1.1

all: run

$(IMAGE):
	wget "$(URL)/$(IMAGE)"

cloud-init.raw: cloud-init/meta-data cloud-init/user-data
	virt-make-fs -F raw -t vfat --label=cidata cloud-init "$@"

data.qcow2:
	qemu-img create -f qcow2 "$@" 20G
	virt-format --filesystem=ext4 --partition=none -a "$@"

sys.qcow2: $(IMAGE)
	qemu-img create -f qcow2 -F qcow2 -b "$^" "$@"

run: sys.qcow2 data.qcow2 cloud-init.raw FORCE
	qemu-system-x86_64 \
		-enable-kvm \
		-cpu host \
		-smp 1 \
		-m 2G \
		-nographic \
		-serial mon:stdio \
		-monitor telnet::1111,server,nowait \
		-drive file="sys.qcow2",index=0,format=qcow2,cache=none,aio=io_uring,if=virtio \
		-drive file="data.qcow2",index=1,format=qcow2,cache=none,aio=io_uring,if=virtio \
		-drive file="cloud-init.raw",index=2,format=raw,cache=none,aio=io_uring,if=virtio \
		-virtfs local,path="$(shell pwd)",mount_tag=host,readonly=on,security_model=none \
		-nic user,model=virtio,hostfwd=tcp:$(LOCALHOST):2222-:22,hostfwd=tcp:$(LOCALHOST):4443-:443

ssh: FORCE
	ssh -i id_debian_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p2222 debian@$(LOCALHOST)

provision: FORCE
	ssh -i id_debian_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p2222 -t debian@$(LOCALHOST) sudo /host/yunohost.sh provision

mon: FORCE
	telnet localhost 1111

clean: FORCE
	$(RM) -r sys.qcow2 data.qcow2

distclean: clean
	$(RM) $(IMAGE) cloud-init.raw

.PHONY: FORCE
