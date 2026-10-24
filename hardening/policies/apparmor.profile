#include <tunables/global>
# Fixture profile: workload-traced Python service, default-deny file/exec policy.
profile breachbench-python-fixture flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  network inet stream,
  network inet dgram,
  signal (send, receive) peer=breachbench-python-fixture,
  signal (receive) peer=unconfined,
  /usr/local/bin/python{,3,3.12} rix,
  /usr/local/lib/** mr,
  /{,usr/}lib/** mr,
  /app/ r,
  /app/** r,
  /etc/ld.so.cache r,
  /etc/nsswitch.conf r,
  /etc/hosts r,
  /etc/resolv.conf r,
  /etc/localtime r,
  /proc/** r,
  /sys/devices/system/cpu/** r,
  /tmp/ rw,
  /tmp/** rw,
  deny /tmp/breachbench-denied rw,
  deny /run/secrets/** rw,
  deny mount,
  deny ptrace,
}
