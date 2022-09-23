
make -f Makefile DEBUG=1
./hashcat -a 0 -m 99998 99998-hash.txt 99998-test.txt --force --potfile-disable --self-test-disable -n 1 -u 1 -T 1 --quiet -d 1
echo "finished"