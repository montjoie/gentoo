# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=5
PYTHON_COMPAT=(python3_4 python3_5)
inherit eutils distutils-r1

if [[ ${PV} =~ [9]{4,} ]]; then
	inherit git-2
	EGIT_REPO_URI="git://github.com/pithos/pithos.git
		https://github.com/pithos/pithos.git"
else
	SRC_URI="https://github.com/${PN}/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"
fi

DESCRIPTION="Pandora.com client for the GNOME desktop"
HOMEPAGE="http://pithos.github.io/"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64"
IUSE="libnotify appindicator +keybinder"

RDEPEND="
	dev-python/pylast[${PYTHON_USEDEP}]
	dev-python/dbus-python[${PYTHON_USEDEP}]
	>=dev-python/pygobject-3.12[${PYTHON_USEDEP}]
	x11-libs/pango[introspection]
	media-libs/gstreamer:1.0[introspection]
	media-plugins/gst-plugins-meta:1.0[aac,http,mp3]
	>=x11-libs/gtk+-3.14:3[introspection]
	x11-themes/gnome-icon-theme-symbolic
	libnotify? ( x11-libs/libnotify[introspection] )
	appindicator? ( dev-libs/libappindicator:3[introspection] )
	keybinder? ( dev-libs/keybinder:3[introspection] )"
DEPEND="${RDEPEND}
	dev-python/setuptools[${PYTHON_USEDEP}]"

python_test() {
	esetup.py test
}
