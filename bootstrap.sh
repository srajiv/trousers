set -x
aclocal || exit 1
libtoolize --force
automake --add-missing -c || exit 1
autoconf || exit 1
