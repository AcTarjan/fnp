#!/bin/bash

md5sum client-input.dat > ci.md5
md5sum server-recv.dat > sr.md5
md5sum client-recv.dat > cr.md5

echo "md5 of client-input.dat: $(cat ci.md5)"
echo "md5 of server-recv.dat : $(cat sr.md5)"
echo "md5 of client-recv.dat : $(cat cr.md5)"

echo "diff client-input.dat server-recv.dat is:"
diff client-input.dat server-recv.dat
echo "diff client-input.dat client-recv.dat is:"
diff client-input.dat client-recv.dat

rm -f *.md5