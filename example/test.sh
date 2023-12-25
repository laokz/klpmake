#!/bin/bash

LOCALE=C
trap catcherr ERR 

declare -i errors=0
function catcherr()
{
	((++errors))
}

# roinit must done first and cannot rmmod
case $(uname -m) in
	aarch64)	tests=(roinit gmemtest memi netlink syscall)
				expect_klpsyms=(3 3 11 0 1)
				expect_check=("" "" "cat /proc/meminfo|grep kpatch" "" "uname|grep kpatch")
				cmd="../../klpmake -b /usr/lib/debug/lib/modules/6.4.0-10.1.0.20.oe2309.aarch64 -s /usr/src/linux-6.4.0-10.1.0.20.oe2309.aarch64"
				;;
	riscv64)	tests=(roinit memi netlink syscall)
				expect_klpsyms=(3 10 0 1)
				expect_check=("" "cat /proc/meminfo|grep kpatch" "" "uname|grep kpatch")
				cmd="../../klpmake -s /var/tmp/build-root/standard_riscv64-riscv64/home/abuild/rpmbuild/BUILD/kernel-6.4.0/linux-6.4.0-10.1.0.21.oe2309.riscv64 -b /var/tmp/build-root/standard_riscv64-riscv64/home/abuild/rpmbuild/BUILD/kernel-6.4.0/linux-6.4.0-10.1.0.21.oe2309.riscv64"
				;;
	x86_64)		tests=(roinit gmemtest memi netlink syscall)
				expect_klpsyms=(3 3 10 0 2)
				expect_check=("" "" "cat /proc/meminfo|grep kpatch" "" "uname|grep kpatch")
				cmd="../../klpmake -s /usr/src/linux-6.4.0-10.1.0.20.oe2309.x86_64 -b /usr/lib/debug/lib/modules/6.4.0-10.1.0.20.oe2309.x86_64"
				;;
	*)			echo "ERROR: not support architecture"
				exit 1
				;;
esac

if lsmod|grep roinit ; then
	echo 0 >/sys/kernel/livepatch/roinit/enabled || true
	rmmod roinit
fi

for ((i=0; i<${#tests[@]}; i++)); do
	cd ${tests[i]}
	eval $cmd
	count=$(cat _klpmake.syms 2>/dev/null|wc -l)
	if ((count != expect_klpsyms[i])); then
		echo "ERROR: unexpectd KLPSYMs of ${test[i]}"
		((++errors))
	fi
	insmod ${tests[i]}.ko
	echo 1 >/sys/kernel/livepatch/${tests[i]}/enabled
	if [[ -n ${expect_check[i]} ]]; then
		eval ${expect_check[i]}
	fi
	if ((i>0)); then
		echo 0 >/sys/kernel/livepatch/${tests[i]}/enabled
		rmmod ${tests[i]}
	fi
	cd ..
done

echo "DONE. ${#tests[@]} tests cost $((SECONDS/60)) minutes, error: $errors"
